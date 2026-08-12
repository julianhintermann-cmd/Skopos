// Package app wires the Skopos subsystems into a running service: it opens
// storage, builds the capture→aggregate→detect→policy→act pipeline, starts the
// HTTP API and runs the periodic maintenance loops. The serve command is a
// thin shell around App.Run.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// App is a fully wired Skopos runtime.
type App struct {
	cfg   *config.Config
	log   *slog.Logger
	demo  bool
	clock func() time.Time
}

// Options tweak how the app runs.
type Options struct {
	// Demo forces the synthetic traffic source regardless of config.
	Demo bool
	// Logger receives structured logs (defaults to stderr text at info level).
	Logger *slog.Logger
}

// New builds an App from configuration.
func New(cfg *config.Config, opts Options) *App {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.Logging.Level)}))
	}
	return &App{
		cfg:   cfg,
		log:   log,
		demo:  opts.Demo || cfg.Demo,
		clock: time.Now,
	}
}

// Run starts every subsystem and blocks until ctx is cancelled, then shuts
// down gracefully. It returns the first fatal error.
func (a *App) Run(ctx context.Context) error {
	// --- storage -----------------------------------------------------------
	st, err := store.Open(store.Options{Path: dbPath(a.cfg)})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() { _ = st.Close() }()

	classifier := flow.NewClassifier(a.cfg.Network.PrivateRanges)

	// --- notification ------------------------------------------------------
	dispatcher := notify.FromConfig(a.cfg)
	dispatcher.SetLogger(a.warnf)

	// --- firewall ----------------------------------------------------------
	backend := firewall.NewNFTablesBackend()
	fw := firewall.NewService(firewall.Config{
		Enforce:        a.cfg.Firewall.Enforcement == "enforce",
		ActionExternal: firewall.Action(a.cfg.Firewall.ActionExternal),
		ActionInternal: firewall.Action(a.cfg.Firewall.ActionInternal),
		DefaultTTL:     a.cfg.Firewall.BlockTTL.Std(),
		IsInternal:     classifier.Internal,
	}, backend, st, a.clock)
	fw.SetLogger(a.warnf)

	degraded := a.cfg.Firewall.Enforcement == "enforce" && !backend.Available()
	if degraded {
		a.log.Warn("firewall backend unavailable — running monitor-only", "backend", backend.Name())
		dispatcher.System(ctx, model.SeverityWarning, "Skopos firewall degraded",
			"The firewall backend is unavailable; Skopos is monitoring but not enforcing blocks.")
	}
	if err := fw.Restore(ctx); err != nil {
		a.log.Error("restoring firewall state", "err", err)
	}
	// Apply static blocklist from config.
	a.applyStaticBlocks(ctx, fw)

	// --- policy ------------------------------------------------------------
	pol := policyFromConfig(a.cfg, classifier, st, dispatcher, fw, a.clock)
	pol.SetLogger(a.warnf)

	// --- detectors + observers --------------------------------------------
	sampler := flow.NewSampler(a.cfg.Capture.SampleThresholdPPS, func(s flow.SampleState) {
		if s.Sampling {
			a.log.Warn("capture sampling engaged", "observed_pps", s.ObservedPPS, "keep_rate", s.KeepRate)
			dispatcher.System(ctx, model.SeverityWarning, "Skopos capture sampling",
				fmt.Sprintf("Traffic exceeded %d pps; sampling to keep up.", s.ObservedPPS))
		} else {
			a.log.Info("capture sampling disengaged")
		}
	})

	live := newLiveMeter(a.clock, sampler.State)
	observers := a.buildObservers(a.cfg, classifier, st, pol, live)

	agg := flow.New(flow.Config{
		Classifier: classifier,
		Sink:       st,
		Observer:   observers,
		Flush:      a.cfg.Capture.FlowFlush.Std(),
	})

	// --- HTTP API ----------------------------------------------------------
	srv, err := api.New(api.Deps{
		Store: st, Firewall: fw, Notifier: dispatcher, Config: a.cfg,
		Live:   live,
		Clock:  a.clock,
		Health: a.healthFunc(st, backend, fw),
	})
	if err != nil {
		return fmt.Errorf("building API: %w", err)
	}
	srv.SetLogger(a.logf)

	// --- run loops ---------------------------------------------------------
	var wg sync.WaitGroup
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	spawn := func(name string, fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	spawn("aggregator", func() { _ = agg.Run(runCtx) })
	spawn("firewall-expiry", func() { fw.ExpireLoop(runCtx, time.Minute) })
	if observers.deviceTracker != nil {
		spawn("devices", func() { _ = observers.deviceTracker.Run(runCtx) })
	}
	a.spawnMaintenance(runCtx, spawn, st, dispatcher)
	a.spawnFeeds(runCtx, spawn, observers.feeds, dispatcher)
	a.spawnCapture(runCtx, spawn, agg, sampler, dispatcher)

	// HTTP server.
	httpSrv := &http.Server{
		Addr:    net.JoinHostPort(a.cfg.Server.Bind, itoa(a.cfg.Server.Port)),
		Handler: srv.Handler(),
	}
	serveErr := make(chan error, 1)
	go func() {
		a.log.Info("listening", "addr", httpSrv.Addr, "auth", a.cfg.Server.Auth.Mode, "enforcement", a.cfg.Firewall.Enforcement)
		serveErr <- serveHTTP(httpSrv, a.cfg)
	}()

	// Startup system notification.
	dispatcher.System(ctx, model.SeverityInfo, "Skopos started",
		fmt.Sprintf("Monitoring is active (enforcement: %s).", a.cfg.Firewall.Enforcement))

	select {
	case <-ctx.Done():
		a.log.Info("shutting down")
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
			wg.Wait()
			return fmt.Errorf("http server: %w", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	return nil
}

func (a *App) logf(format string, args ...any) { a.log.Info(fmt.Sprintf(format, args...)) }

// warnf is the logger handed to subsystems whose callbacks fire on abnormal
// conditions — a failed notification, a refused block, a degraded backend.
// Routing those through Info would bury exactly the lines worth noticing.
func (a *App) warnf(format string, args ...any) { a.log.Warn(fmt.Sprintf(format, args...)) }

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (a *App) applyStaticBlocks(ctx context.Context, fw *firewall.Service) {
	for _, entry := range a.cfg.Firewall.Blocklist {
		prefix, err := parsePrefix(entry)
		if err != nil {
			a.log.Warn("skipping invalid blocklist entry", "entry", entry, "err", err)
			continue
		}
		if err := fw.ManualBlock(ctx, prefix, "config", "static blocklist", 0); err != nil {
			a.log.Warn("applying static block", "prefix", entry, "err", err)
		}
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
