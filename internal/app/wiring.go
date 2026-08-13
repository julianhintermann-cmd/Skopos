package app

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/capture"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/policy"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/version"
)

// gate wraps an observer with a runtime on/off switch, so a detector can be
// disabled from the dashboard without rebuilding the pipeline. Disabled
// detectors keep their state but see no packets.
type gate struct {
	obs flow.Observer
	on  atomic.Bool
}

func newGate(obs flow.Observer, on bool) *gate {
	g := &gate{obs: obs}
	g.on.Store(on)
	return g
}

func (g *gate) Observe(p flow.Packet) {
	if g.on.Load() {
		g.obs.Observe(p)
	}
}

// observerSet is the fan-out flow.Observer plus references to the pieces that
// need their own loops or runtime reconfiguration.
type observerSet struct {
	all           []flow.Observer
	feeds         *detect.Feeds
	deviceTracker *capture.DeviceTracker
	portscan      *detect.Portscan
	portscanGate  *gate
	rate          *detect.Rate
	rateGate      *gate
}

// Observe implements flow.Observer by forwarding to every sub-observer.
func (o *observerSet) Observe(p flow.Packet) {
	for _, obs := range o.all {
		obs.Observe(p)
	}
}

// buildObservers assembles the detector fan-out from configuration.
func (a *App) buildObservers(cfg *config.Config, classifier *flow.Classifier, st *store.Store, pol *policy.Engine, live *liveMeter) *observerSet {
	set := &observerSet{}
	// Live meter first so it counts every packet.
	set.all = append(set.all, live)

	// Both threshold detectors are always constructed and gated, so the
	// dashboard can switch them on and off without a restart.
	{
		set.portscan = detect.NewPortscan(detect.PortscanConfig{
			Window:     cfg.Detection.Portscan.Window.Std(),
			External:   detect.Thresholds{Ports: cfg.Detection.Portscan.External.Ports, Targets: cfg.Detection.Portscan.External.Targets},
			Internal:   detect.Thresholds{Ports: cfg.Detection.Portscan.Internal.Ports, Targets: cfg.Detection.Portscan.Internal.Targets},
			Severity:   model.Severity(cfg.Detection.Portscan.Severity),
			Block:      cfg.Detection.Portscan.Block,
			IsInternal: classifier.Internal,
		}, pol, a.clock)
		set.portscanGate = newGate(set.portscan, cfg.Detection.Portscan.Enabled)
		set.all = append(set.all, set.portscanGate)

		set.rate = detect.NewRate(detect.RateConfig{
			Window:              cfg.Detection.Rate.Window.Std(),
			MaxNewConnections:   cfg.Detection.Rate.MaxNewConnections,
			MaxPacketsPerSecond: cfg.Detection.Rate.MaxPacketsPerSecond,
			Severity:            model.Severity(cfg.Detection.Rate.Severity),
			Block:               cfg.Detection.Rate.Block,
		}, pol, a.clock)
		set.rateGate = newGate(set.rate, cfg.Detection.Rate.Enabled)
		set.all = append(set.all, set.rateGate)
	}
	if cfg.Detection.Feeds.Enabled {
		set.feeds = detect.NewFeeds(detect.FeedsConfig{
			Lists:      cfg.Detection.Feeds.Lists,
			Refresh:    cfg.Detection.Feeds.Refresh.Std(),
			Severity:   model.Severity(cfg.Detection.Feeds.Severity),
			Block:      cfg.Detection.Feeds.Block,
			IsInternal: classifier.Internal,
		}, pol, detect.NewHTTPFetcher(), a.clock)
		set.all = append(set.all, set.feeds)
	}

	// Device inventory and the new-device detector, when capture supports it.
	if cfg.Capture.Devices {
		var onNew capture.NewDeviceFunc
		if cfg.Detection.NewDevice.Enabled {
			nd := detect.NewNewDevice(detect.NewDeviceConfig{
				Severity: model.Severity(cfg.Detection.NewDevice.Severity),
			}, pol)
			onNew = nd.Report
		}
		set.deviceTracker = capture.NewDeviceTracker(classifier, st, onNew, cfg.Capture.FlowFlush.Std())
		set.all = append(set.all, set.deviceTracker)
	}

	return set
}

// policyFromConfig builds the policy engine.
func policyFromConfig(cfg *config.Config, classifier *flow.Classifier, st *store.Store, disp *notify.Dispatcher, fw *firewall.Service, clock func() time.Time) *policy.Engine {
	var allow []netip.Prefix
	for _, e := range cfg.Firewall.Allowlist {
		if p, err := parsePrefix(e); err == nil {
			allow = append(allow, p)
		}
	}

	enforcement := policy.Observe
	if cfg.Firewall.Enforcement == "enforce" {
		enforcement = policy.Enforce
	}

	return policy.New(policy.Config{
		Enforcement: enforcement,
		Cooldown:    cfg.Detection.Cooldown.Std(),
		BlockTTL:    cfg.Firewall.BlockTTL.Std(),
		QuietHours: policy.QuietHours{
			Enabled:     cfg.Detection.QuietHours.Enabled,
			From:        clockToTime(cfg.Detection.QuietHours.From),
			To:          clockToTime(cfg.Detection.QuietHours.To),
			MinSeverity: model.Severity(cfg.Detection.QuietHours.MinSeverity),
		},
		Allowlist: allow,
		Gateway:   resolveGateway(),
	}, st, disp, fw, clock)
}

func clockToTime(c config.ClockTime) time.Time {
	return time.Date(0, 1, 1, c.Hour, c.Minute, 0, 0, time.UTC)
}

// healthFunc reports subsystem health for /api/health.
func (a *App) healthFunc(st *store.Store, backend firewall.Backend, fw *firewall.Service) func() api.Health {
	return func() api.Health {
		h := api.Health{OK: true, Enforcing: fw.Enforcing(), Version: version.Version}
		if a.demo {
			h.Capture = "demo"
		} else {
			h.Capture = "afpacket"
		}
		h.Firewall = backend.Name()
		// DB writable check.
		if _, err := st.CountUnackedAlerts(context.Background()); err != nil {
			h.OK = false
			h.Detail = "database not writable: " + err.Error()
		}
		// Cold storage reachability.
		h.ColdOK = coldStorageOK(a.cfg.Storage.Cold)
		return h
	}
}
