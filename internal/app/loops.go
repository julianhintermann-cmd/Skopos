package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/capture"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// spawnCapture starts the capture source(s), applying the sampler before
// handing each kept packet to the aggregator.
func (a *App) spawnCapture(ctx context.Context, spawn func(string, func()), agg *flow.Aggregator, sampler *flow.Sampler, disp *notify.Dispatcher) {
	// The aggregator writes the coverage heartbeat alongside the flows, so it
	// needs the registry the sources report into.
	health := sampler.Health()
	agg.SetCaptureHealth(health)

	handle := func(p flow.Packet) {
		if sampler.Keep() {
			agg.Add(p)
		}
	}

	// Sampler measurement loop, which doubles as the coverage heartbeat. It
	// ticks on the clock rather than on traffic, and that independence is the
	// point: a minute with no packets still records that the capture was up
	// for it, so a quiet network stops looking like a dead one.
	spawn("sampler", func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		last := a.clock()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				health.Tick(now, sampler.Measure(now.Sub(last)))
				last = now
			}
		}
	})

	// Sources are registered before any of them starts, so sources_total is
	// right from the first heartbeat and one that never opens its interface
	// reads as configured-and-down rather than as absent.
	run := func(src capture.Source) {
		health.Up(src.Name())
		defer health.Down(src.Name())
		if err := src.Run(ctx, handle); err != nil && ctx.Err() == nil {
			a.log.Error("capture source stopped", "source", src.Name(), "err", err)
			disp.System(ctx, model.SeverityWarning, "Skopos capture stopped",
				"A capture source stopped: "+err.Error())
		}
	}

	if a.demo {
		src := capture.NewDemoSource(capture.DemoOptions{})
		health.Register(src.Name())
		spawn("demo-source", func() { run(src) })
		return
	}

	for _, iface := range resolveInterfaces(a.cfg.Interfaces) {
		src := capture.NewInterfaceSource(iface)
		health.Register(src.Name())
		spawn("capture:"+iface, func() { run(src) })
	}
}

// spawnFeeds refreshes blocklist feeds on the configured interval.
func (a *App) spawnFeeds(ctx context.Context, spawn func(string, func()), feeds *detect.Feeds, disp *notify.Dispatcher) {
	if feeds == nil {
		return
	}
	spawn("feeds", func() {
		refresh := func() {
			n, err := feeds.Refresh(ctx)
			if err != nil {
				a.log.Warn("feed refresh had failures", "err", err, "loaded", n)
				disp.System(ctx, model.SeverityWarning, "Skopos feed update failed", err.Error())
				return
			}
			a.log.Info("feeds refreshed", "prefixes", n)
		}
		refresh() // initial load
		t := time.NewTicker(a.cfg.Detection.Feeds.Refresh.Std())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	})
}

// spawnMaintenance runs the device flush, retention, archive and backup jobs.
func (a *App) spawnMaintenance(ctx context.Context, spawn func(string, func()), st *store.Store, disp *notify.Dispatcher) {
	// Retention + hot-size cap, hourly.
	spawn("retention", func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := st.ApplyRetention(ctx, retentionFromConfig(a.cfg)); err != nil {
					a.log.Warn("retention", "err", err)
				}
				switch _, err := st.EnforceHotLimit(ctx, a.cfg.Storage.HotMaxSize.Bytes()); {
				case errors.Is(err, store.ErrHotLimitUnreachable):
					// The cap has stopped being a cap. Every run from now on
					// empties the raw flows and the documented retention
					// window is gone, so this is worth waking someone for.
					a.log.Error("hot-storage cap unreachable", "err", err)
					disp.System(ctx, model.SeverityWarning, "Skopos is out of hot storage",
						err.Error()+". Raise storage.hot_max_size, or shorten the rollup retention — "+
							"raw-flow history is being deleted almost as fast as it is written.")
				case err != nil:
					a.log.Warn("hot-limit enforcement", "err", err)
				}
				// Passive DNS follows the raw-flow retention: names outlive
				// the flows that taught them by exactly one retention window,
				// which is what makes older history still readable.
				cutoff := a.clock().Add(-a.cfg.Storage.Retention.Rollup1h.Std())
				if err := st.PruneNames(ctx, cutoff); err != nil {
					a.log.Warn("pruning names", "err", err)
				}
				// Incidents follow the same window. The pruner existed but
				// nothing ever called it, so the table only ever grew.
				if err := st.PruneIncidents(ctx, cutoff); err != nil {
					a.log.Warn("pruning incidents", "err", err)
				}
			}
		}
	})

	// Daily backup near the configured time.
	if a.cfg.Storage.Backup.Enabled {
		spawn("backup", func() {
			runDaily(ctx, a.clock, a.cfg.Storage.Backup.At, func() {
				dir := filepath.Join(a.cfg.Storage.Cold, "backups")
				if _, err := st.Backup(ctx, dir, a.cfg.Storage.Backup.Keep); err != nil {
					a.log.Warn("backup failed", "err", err)
					disp.System(ctx, model.SeverityWarning, "Skopos backup failed", err.Error())
				} else {
					a.log.Info("backup complete", "dir", dir)
				}
			})
		})
	}
}

func retentionFromConfig(cfg *config.Config) store.RetentionPolicy {
	return store.RetentionPolicy{
		RawFlows: cfg.Storage.Retention.RawFlows.Std(),
		Rollup1m: cfg.Storage.Retention.Rollup1m.Std(),
		Rollup1h: cfg.Storage.Retention.Rollup1h.Std(),
		Rollup1d: cfg.Storage.Retention.Rollup1d.Std(),
	}
}

// runDaily invokes fn once per day at the given local clock time.
func runDaily(ctx context.Context, clock func() time.Time, at config.ClockTime, fn func()) {
	for {
		now := clock()
		next := time.Date(now.Year(), now.Month(), now.Day(), at.Hour, at.Minute, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		timer := time.NewTimer(next.Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			fn()
		}
	}
}

// serveHTTP starts the HTTP server, with native TLS when configured.
func serveHTTP(srv *http.Server, cfg *config.Config) error {
	if cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return srv.ListenAndServeTLS(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
	}
	return srv.ListenAndServe()
}

// coldStorageOK reports whether the cold-storage path is a writable directory.
func coldStorageOK(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	probe := filepath.Join(path, ".skopos-write-test")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}
