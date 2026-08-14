package app

import (
	"context"
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/policy"
	"github.com/julianhintermann-cmd/skopos/internal/settings"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// runtimeBaseline projects the YAML configuration onto the editable subset,
// which is the baseline every override layers onto.
func runtimeBaseline(cfg *config.Config) settings.Runtime {
	return settings.Runtime{
		Enforcement: cfg.Firewall.Enforcement,
		BlockTTL:    cfg.Firewall.BlockTTL.Std(),
		Allowlist:   append([]string(nil), cfg.Firewall.Allowlist...),
		Cooldown:    cfg.Detection.Cooldown.Std(),
		QuietHours: settings.QuietHours{
			Enabled:     cfg.Detection.QuietHours.Enabled,
			FromHour:    cfg.Detection.QuietHours.From.Hour,
			FromMinute:  cfg.Detection.QuietHours.From.Minute,
			ToHour:      cfg.Detection.QuietHours.To.Hour,
			ToMinute:    cfg.Detection.QuietHours.To.Minute,
			MinSeverity: cfg.Detection.QuietHours.MinSeverity,
		},
		Portscan: settings.Portscan{
			Enabled:  cfg.Detection.Portscan.Enabled,
			Window:   cfg.Detection.Portscan.Window.Std(),
			External: settings.Thresholds{Ports: cfg.Detection.Portscan.External.Ports, Targets: cfg.Detection.Portscan.External.Targets},
			Internal: settings.Thresholds{Ports: cfg.Detection.Portscan.Internal.Ports, Targets: cfg.Detection.Portscan.Internal.Targets},
			Block:    cfg.Detection.Portscan.Block,
		},
		Rate: settings.Rate{
			Enabled:             cfg.Detection.Rate.Enabled,
			Window:              cfg.Detection.Rate.Window.Std(),
			MaxNewConnections:   cfg.Detection.Rate.MaxNewConnections,
			MaxPacketsPerSecond: cfg.Detection.Rate.MaxPacketsPerSecond,
			Block:               cfg.Detection.Rate.Block,
		},
	}
}

// applySettings pushes one set of effective settings into the live
// subsystems. Called once at startup and again on every change, so startup
// and runtime take exactly the same path — there is no second code path that
// could drift.
//
// It returns what the subsystems refused rather than only logging it. These
// two errors used to go to the log and no further, which is how POST
// /api/settings came to answer ok:true over a kernel that had just declined to
// arm the firewall: the operator armed it, the page said armed, and nothing
// was being dropped. A log line is not an answer to the caller who asked.
//
// Every step still runs after a failure. The settings are independent, and
// abandoning the detectors because the kernel refused enforcement would turn
// one refusal into several.
func (a *App) applySettings(ctx context.Context, r settings.Runtime,
	fw *firewall.Service, pol *policy.Engine, obs *observerSet, st *store.Store) settings.ApplyResult {

	var res settings.ApplyResult

	// Firewall: enforcement first, since it is the one with kernel effects.
	if err := fw.SetEnforce(ctx, r.Enforcement == "enforce"); err != nil {
		a.log.Error("applying enforcement", "err", err)
		res.Fail("enforcement", err)
	}
	fw.SetDefaultTTL(r.BlockTTL)

	// Policy: cooldown, TTL, quiet hours, allowlist.
	var allow []netip.Prefix
	for _, e := range r.Allowlist {
		if p, err := settings.ParsePrefix(e); err == nil {
			allow = append(allow, p)
		}
	}
	enforcement := policy.Observe
	if r.Enforcement == "enforce" {
		enforcement = policy.Enforce
	}
	// The firewall gets the same list, so a block placed by hand is held to
	// the rule the detectors have always been held to. pol.Apply adds the
	// gateway itself; ask it afterwards rather than deriving it twice.
	pol.Apply(enforcement, r.Cooldown, r.BlockTTL, policy.QuietHours{
		Enabled:     r.QuietHours.Enabled,
		From:        clockToTime(config.ClockTime{Hour: r.QuietHours.FromHour, Minute: r.QuietHours.FromMinute}),
		To:          clockToTime(config.ClockTime{Hour: r.QuietHours.ToHour, Minute: r.QuietHours.ToMinute}),
		MinSeverity: severityOr(r.QuietHours.MinSeverity, "critical"),
	}, allow)
	if err := fw.SetProtected(ctx, pol.ProtectedPrefixes()); err != nil {
		a.log.Error("applying the never-block list", "err", err)
		// Reported against "allowlist": that is the field the operator edited
		// and the one they can fix, not the internal call that failed.
		res.Fail("allowlist", err)
	}

	// Detectors.
	if obs.portscan != nil {
		obs.portscan.SetThresholds(r.Portscan.Window,
			detect.Thresholds{Ports: r.Portscan.External.Ports, Targets: r.Portscan.External.Targets},
			detect.Thresholds{Ports: r.Portscan.Internal.Ports, Targets: r.Portscan.Internal.Targets},
			r.Portscan.Block)
		obs.portscanGate.on.Store(r.Portscan.Enabled)
	}
	if obs.rate != nil {
		obs.rate.SetLimits(r.Rate.Window, r.Rate.MaxNewConnections, r.Rate.MaxPacketsPerSecond, r.Rate.Block)
		obs.rateGate.on.Store(r.Rate.Enabled)
	}
	return res
}

// severityOr falls back when the stored value is empty.
func severityOr(s, fallback string) model.Severity {
	if s == "" {
		s = fallback
	}
	return model.Severity(s)
}

// settingsAuditor records every change in the audit log, so "who armed the
// firewall at 3am" has an answer.
//
// The detail is worded as a request because that is all this subscriber knows.
// It runs alongside the apply, not after it, so it cannot see whether the
// kernel took the change; reading "enforcement=enforce" here as proof of
// enforcement is the same mistake the endpoint used to make. The outcome is
// audited separately as settings_apply_failed by the handler that has it.
func settingsAuditor(st *store.Store, clock func() time.Time) func(settings.Runtime) {
	return func(r settings.Runtime) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = st.Audit(ctx, model.AuditEntry{
			Time: clock(), Actor: "settings", Action: "settings_applied",
			Detail: "requested enforcement=" + r.Enforcement,
		})
	}
}

// syncDevicePolicies keeps the kernel's per-device rules aligned with the
// device inventory. A device's address can change with DHCP, so the rules are
// re-derived on an interval rather than only when the operator edits them.
func (a *App) syncDevicePolicies(ctx context.Context, st *store.Store, fw *firewall.Service) {
	a.applyDevicePoliciesOnce(ctx, st, fw)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.applyDevicePoliciesOnce(ctx, st, fw)
		}
	}
}

// applyDevicePoliciesOnce derives the kernel rules from the inventory and
// pushes them.
func (a *App) applyDevicePoliciesOnce(ctx context.Context, st *store.Store, fw *firewall.Service) {
	devices, err := st.RestrictedDevices(ctx)
	if err != nil {
		a.warnf("device policies: loading: %v", err)
		return
	}
	rules := make([]firewall.DeviceRule, 0, len(devices))
	for _, d := range devices {
		var policy firewall.DevicePolicy
		switch d.Policy {
		case model.PolicyLANOnly:
			policy = firewall.DeviceLANOnly
		case model.PolicyQuarantine:
			policy = firewall.DeviceQuarantine
		default:
			continue
		}
		// Every address the device answers on, not just its IPv4 one: a
		// quarantine with a working IPv6 path is not a quarantine.
		for _, addr := range d.Addrs() {
			rules = append(rules, firewall.DeviceRule{Addr: addr, Policy: policy})
		}
	}
	if err := fw.SetDevicePolicies(ctx, rules); err != nil {
		a.warnf("device policies: applying: %v", err)
	}
}
