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
	"path/filepath"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/blockwatch"
	"github.com/julianhintermann-cmd/skopos/internal/cloudflare"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/geoip"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/names"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/policy"
	"github.com/julianhintermann-cmd/skopos/internal/reputation"
	"github.com/julianhintermann-cmd/skopos/internal/secret"
	"github.com/julianhintermann-cmd/skopos/internal/settings"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/updatecheck"
	"github.com/julianhintermann-cmd/skopos/internal/version"
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

	// --- cloudflare integration -------------------------------------------
	// The token is entered in the UI and sealed at rest; nothing here is
	// configured from the YAML. A failure to build the secret box is fatal —
	// it would mean the store cannot hold secrets.
	secretBox, err := secret.FromStore(st)
	if err != nil {
		return fmt.Errorf("opening secret store: %w", err)
	}
	cf := cloudflare.NewManager(st, secretBox, cloudflare.NewClient(), a.clock)

	// --- geoip -------------------------------------------------------------
	// Country lookups run locally against the DB-IP Lite database, refreshed
	// like the blocklist feeds. Demo mode ships a static mapping instead.
	countries, err := geoip.NewBlocklist(st)
	if err != nil {
		return fmt.Errorf("loading country blocklist: %w", err)
	}
	var geo geoip.Provider
	if a.demo {
		geo = geoip.NewDemoProvider()
	} else {
		gm := geoip.NewManager(filepath.Join(a.cfg.Storage.Hot, "geoip"), a.clock)
		gm.SetLogger(a.warnf)
		gm.Start(ctx)
		geo = gm
	}

	classifier := flow.NewClassifier(a.cfg.Network.PrivateRanges)

	// --- notification ------------------------------------------------------
	dispatcher := notify.FromConfig(a.cfg)
	dispatcher.SetLogger(a.warnf)
	// Annotate alert sources with the device's name where one is known, so a
	// push reads "192.168.1.23 (Living-room TV)" instead of a bare address.
	dispatcher.SetNameResolver(func(addr netip.Addr) string {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		name, err := st.DeviceNameByIP(ctx, addr.String())
		if err != nil {
			return ""
		}
		return name
	})

	// --- firewall ----------------------------------------------------------
	backend := firewall.NewNFTablesBackend(classifier.Ranges())
	fw := firewall.NewService(firewall.Config{
		Enforce:        a.cfg.Firewall.Enforcement == "enforce",
		ActionExternal: firewall.Action(a.cfg.Firewall.ActionExternal),
		ActionInternal: firewall.Action(a.cfg.Firewall.ActionInternal),
		DefaultTTL:     a.cfg.Firewall.BlockTTL.Std(),
		IsInternal:     classifier.Internal,
	}, backend, st, a.clock)
	fw.SetLogger(a.warnf)

	enforceOn := a.cfg.Firewall.Enforcement == "enforce"
	backendAvail := backend.Available()
	enforceActive := enforceOn && backendAvail
	if enforceOn && !backendAvail {
		a.log.Warn("firewall backend unavailable — running monitor-only", "backend", backend.Name())
		dispatcher.System(ctx, model.SeverityWarning, "Skopos firewall degraded",
			"The firewall backend is unavailable; Skopos is monitoring but not enforcing blocks.")
	}
	// The never-block list has to be in place before anything is restored or
	// blocked, or the first thing Skopos does on a cold start is apply the
	// blocks it would refuse a second later. applySettings sets it again from
	// the effective settings; this is the same list, early.
	if err := fw.SetProtected(ctx, protectedFromConfig(a.cfg)); err != nil {
		a.log.Error("applying the never-block list", "err", err)
	}
	if err := fw.Restore(ctx); err != nil {
		a.log.Error("restoring firewall state", "err", err)
	}
	// Apply static blocklist from config.
	a.applyStaticBlocks(ctx, fw)

	// Preventive country blocking: keep the kernel's country sets in sync
	// with the blocked-country list and the GeoIP database.
	countryEnf := newCountryEnforcer(geo, countries, fw, enforceActive, a.logf, a.warnf)

	// Blocked traffic is still captured — the tap sits before netfilter — so
	// tally those packets per block: live proof the firewall works, and in
	// observe mode a preview of what enforcing would drop.
	watch := blockwatch.New()
	if blocks, err := st.ActiveBlocks(ctx); err == nil {
		watch.Update(blocks)
	}

	// --- policy ------------------------------------------------------------
	pol := policyFromConfig(a.cfg, classifier, st, dispatcher, fw, a.clock)
	// Operator mute rules: noise control that never touches blocking.
	muter := policy.NewMuter()
	pol.SetMuter(muter)
	reloadMutes := func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rules, err := st.ListMuteRules(c)
		if err != nil {
			a.warnf("mutes: loading: %v", err)
			return
		}
		out := make([]policy.MuteRule, 0, len(rules))
		for _, r := range rules {
			m := policy.MuteRule{Detector: r.Detector, Port: r.Port, Expires: r.Expires}
			if r.Prefix != "" {
				p, err := netip.ParsePrefix(r.Prefix)
				if err != nil {
					continue
				}
				m.Prefix = p
			}
			out = append(out, m)
		}
		muter.Replace(out)
	}
	reloadMutes()
	if enforceActive {
		// Sources the kernel is already dropping raise no further alerts;
		// their ongoing attempts show in the per-block counters instead.
		pol.SetAlreadyBlocked(watch.Contains)
	}
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
	// Blocked-country watch: reactive blocking of inbound sources from listed
	// countries, throttled per source; policy still owns cooldown/allowlist.
	// It backs up the preventive sets — and carries the feature alone while
	// the GeoIP database is still downloading.
	observers.all = append(observers.all, detect.NewCountryBlock(detect.CountryBlockConfig{
		Lookup:     geo.Lookup,
		Blocked:    countries.Contains,
		Empty:      countries.Empty,
		IsInternal: classifier.Internal,
		Covered:    countryEnf.Covered,
	}, pol, a.clock))
	// Per-block attempt tallies from the same packet stream.
	observers.all = append(observers.all, watch)
	// Passive DNS: learn address→name from DNS/mDNS answers and TLS SNI, so
	// the dashboard can say "youtube.com" instead of "142.250.185.78".
	resolver := names.New(st, classifier.Internal, a.clock)
	resolver.SetLogger(a.warnf)
	if err := resolver.Warm(ctx); err != nil {
		a.log.Warn("loading known names", "err", err)
	}
	observers.all = append(observers.all, resolver)
	// The same passive names inventory the device list: a printer announcing
	// itself over mDNS is filed as "printer.local", not as a bare MAC.
	if observers.deviceTracker != nil {
		observers.deviceTracker.SetHostnameLookup(resolver.Lookup)
	}

	// --- runtime settings ---------------------------------------------------
	// The YAML is the baseline; the dashboard layers overrides on top and both
	// land through the same apply path, at startup and on every change.
	setman, err := settings.New(st, runtimeBaseline(a.cfg))
	if err != nil {
		return fmt.Errorf("loading runtime settings: %w", err)
	}
	a.applySettings(ctx, setman.Current(), fw, pol, observers, st)
	setman.OnChange(func(r settings.Runtime) {
		a.applySettings(context.Background(), r, fw, pol, observers, st)
	})
	setman.OnChange(settingsAuditor(st, a.clock))

	// Tee the flow sink: every flushed batch is written to the store as before
	// and, in addition, projected for the live view — streamed to dashboards
	// over SSE and kept in a bounded ring so a freshly opened view back-fills.
	// Flows the kernel is dropping are flagged so the live view can say
	// "arriving, but dropped" instead of looking like a firewall failure —
	// only when something is actually dropped: never in observe mode, and
	// for country coverage only on inbound-initiated flows (established
	// flows the LAN opened itself are exempted by conntrack).
	blockedFlow := func(f model.Flow) bool {
		if !enforceActive {
			return false
		}
		if watch.Contains(f.SrcIP) || watch.Contains(f.DstIP) {
			return true
		}
		return f.Dir == model.DirWANtoLAN && countryEnf.Covered(f.SrcIP)
	}
	// Domain contacts ride the same batches: one row per device/domain/hour.
	domains := newDomainRecorder(st, st, classifier.Internal, a.warnf)
	liveSink := newLiveFlows(domains, nil, blockedFlow)

	agg := flow.New(flow.Config{
		Classifier: classifier,
		Sink:       liveSink,
		Observer:   observers,
		Flush:      a.cfg.Capture.FlowFlush.Std(),
		NameLookup: resolver.Lookup,
	})

	runSpeedtest := a.speedtestFunc(st, dispatcher)
	// "Who is this?" draws on what Skopos already has before it asks anyone:
	// the GeoIP database knows where an address actually is, which is not the
	// country a registry records for the holder, and the downloaded
	// blocklists already have an opinion about it.
	rep := reputation.New(a.clock)
	rep.Geo = geo.Lookup
	if observers.feeds != nil {
		rep.Listed = observers.feeds.Listed
	}

	// Release check: a monitoring tool quietly running a stale image is a
	// failure mode of its own. One notification per new version, never a
	// nag; the System view carries the state.
	updates := updatecheck.New(version.Version, a.clock)
	updates.SetNotifier(func(v, url string) {
		dispatcher.System(ctx, model.SeverityInfo, "Skopos "+v+" is available",
			"A newer release is published. Release notes: "+url)
	})

	// Applying device policies on demand, so an edit in the UI reaches the
	// kernel immediately instead of at the next sync tick.
	applyDevicePolicies := func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.applyDevicePoliciesOnce(c, st, fw)
	}

	// --- HTTP API ----------------------------------------------------------
	srv, err := api.New(api.Deps{
		Store: st, Firewall: fw, Notifier: dispatcher, Config: a.cfg,
		Live:                live,
		LiveFlows:           liveSink,
		Cloudflare:          cf,
		Speedtest:           runSpeedtest,
		GeoIP:               geo,
		Countries:           countries,
		Reputation:          rep,
		PolicyDropped:       pol.DroppedFindings,
		BlockStats:          watch.Stats,
		CountryBlockStats:   countryEnf.Stats,
		Updates:             updates.Status,
		Settings:            setman,
		ApplyDevicePolicies: applyDevicePolicies,
		ReloadMutes:         reloadMutes,
		Clock:               a.clock,
		Health:              a.healthFunc(st, backend, fw),
	})
	if err != nil {
		return fmt.Errorf("building API: %w", err)
	}
	srv.SetLogger(a.logf)
	// Notifications carry working buttons: the API mints a signed link per
	// alert that authorises exactly one block or mute.
	dispatcher.SetActionBuilder(srv.AlertActions)
	// Now that the hub exists, let the tee publish to it. This assignment
	// happens-before the aggregator goroutine starts, so no lock is needed.
	liveSink.hub = srv.Hub()

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

	// The policy worker starts before capture: from here on, a detector
	// firing hands its finding to this goroutine instead of doing the
	// database write, the notification and the netlink call on the goroutine
	// that is supposed to be reading packets off the wire.
	spawn("policy", func() { pol.Run(runCtx) })
	spawn("aggregator", func() { _ = agg.Run(runCtx) })
	spawn("firewall-expiry", func() { fw.ExpireLoop(runCtx, time.Minute) })
	spawn("country-enforcer", func() { countryEnf.run(runCtx) })
	if a.cfg.Updates.Check {
		spawn("update-check", func() { updates.Run(runCtx) })
	}
	spawn("blockwatch", func() { a.refreshBlockWatch(runCtx, st, watch) })
	spawn("names", func() { resolver.Run(runCtx, 30*time.Second) })
	spawn("device-policies", func() { a.syncDevicePolicies(runCtx, st, fw) })
	spawn("domains", func() { domains.Run(runCtx, time.Minute) })
	spawn("live-broadcast", func() { a.broadcastLive(runCtx, srv.Hub(), live) })
	if observers.deviceTracker != nil {
		spawn("devices", func() { _ = observers.deviceTracker.Run(runCtx) })
	}
	a.spawnMaintenance(runCtx, spawn, st, dispatcher)
	a.spawnFeeds(runCtx, spawn, observers.feeds, dispatcher)
	a.spawnCapture(runCtx, spawn, agg, sampler, dispatcher)
	a.spawnPresence(runCtx, spawn, st, dispatcher)
	a.spawnWeeklyReport(runCtx, spawn, st, dispatcher)
	a.spawnSpeedtest(runCtx, spawn, runSpeedtest)

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

// refreshBlockWatch keeps the block watcher's matcher aligned with the stored
// active blocks. Five seconds of lag is invisible next to the policy cooldown
// and keeps the packet path free of database reads.
func (a *App) refreshBlockWatch(ctx context.Context, st *store.Store, w *blockwatch.Watch) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if blocks, err := st.ActiveBlocks(ctx); err == nil {
				w.Update(blocks)
			}
		}
	}
}

// broadcastLive pushes the current throughput snapshot to dashboards once a
// second, giving the live view a real-time reading without every open browser
// polling the API.
func (a *App) broadcastLive(ctx context.Context, hub eventPublisher, live *liveMeter) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hub.Publish(api.Event{Type: "live", Data: live.Snapshot()})
		}
	}
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

// protectedFromConfig derives the never-block list straight from the YAML,
// for the window before the settings layer is up. It mirrors what the policy
// engine computes: the configured allowlist plus the default gateways.
func protectedFromConfig(cfg *config.Config) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range cfg.Firewall.Allowlist {
		if p, err := parsePrefix(e); err == nil {
			out = append(out, p)
		}
	}
	for _, gw := range resolveGateways() {
		out = append(out, netip.PrefixFrom(gw, gw.BitLen()))
	}
	return out
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
