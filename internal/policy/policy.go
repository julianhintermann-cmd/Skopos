// Package policy turns raw detector findings into actions. It owns everything
// the detectors deliberately do not: alert severity handling, per-source
// cooldown with aggregation, nightly quiet hours, the never-block allowlist
// (with the gateway hard-wired), and the observe/enforce switch that decides
// whether a suggested block actually reaches the firewall.
package policy

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/netset"
)

// AlertStore persists alerts and returns the stored record (with its ID).
// Grouping is optional: a store that does not implement Incidenter simply
// records alerts flat.
type AlertStore interface {
	InsertAlert(ctx context.Context, a model.Alert) (model.Alert, error)
}

// Incidenter files a stored alert into an episode for its source, so the UI
// can show one attacker rather than forty rows.
type Incidenter interface {
	AttachToIncident(ctx context.Context, a model.Alert) (int64, error)
}

// Notifier delivers an alert to the outside world (ntfy, webhook).
type Notifier interface {
	Notify(ctx context.Context, a model.Alert)
}

// Blocker applies a firewall block. Called only when enforcement is on and the
// source survives the allowlist.
type Blocker interface {
	Block(ctx context.Context, prefix netip.Prefix, reason string, ttl time.Duration) error
}

// Enforcement is the global observe/enforce switch.
type Enforcement string

const (
	Observe Enforcement = "observe"
	Enforce Enforcement = "enforce"
)

// Config configures the policy engine.
type Config struct {
	Enforcement Enforcement
	Cooldown    time.Duration
	BlockTTL    time.Duration

	QuietHours QuietHours

	// Allowlist holds never-block prefixes. The gateway is protected in
	// addition, regardless of this list.
	Allowlist []netip.Prefix
	// Gateway is always protected from blocking (the last-resort safety so
	// Skopos can never lock you out of your own network).
	Gateway netip.Addr
	// Muter, when set, suppresses matching findings' alerts and
	// notifications. Blocking is unaffected: silencing a nuisance must not
	// silently disarm the protection that goes with it.
	Muter *Muter
	// AlreadyBlocked, when set, reports that a source is inside an active,
	// actually-enforced block. Findings for such sources are dropped
	// entirely: the kernel is discarding their packets, and re-alerting on
	// traffic that only the capture tap still sees would read as the block
	// not working. Wire it only when enforcement is really on — in observe
	// mode nothing is dropped, so alerts must keep flowing.
	AlreadyBlocked func(netip.Addr) bool
}

// QuietHours suppresses low-severity notifications during a nightly window.
type QuietHours struct {
	Enabled     bool
	From        time.Time // only clock time (hour, minute) is used
	To          time.Time
	MinSeverity model.Severity
}

// Engine is the policy engine. It implements detect.Sink.
type Engine struct {
	cfg      Config
	store    AlertStore
	notifier Notifier
	blocker  Blocker
	clock    func() time.Time
	log      func(string, ...any)

	allow *netset.Set

	mu       sync.Mutex
	cooldown map[string]*cooldownState
}

type cooldownState struct {
	lastNotified time.Time
	suppressed   int // occurrences counted since the last notification
}

// New creates a policy engine.
func New(cfg Config, store AlertStore, notifier Notifier, blocker Blocker, clock func() time.Time) *Engine {
	if clock == nil {
		clock = time.Now
	}
	allow := netset.New()
	for _, p := range cfg.Allowlist {
		allow.Add(p)
	}
	if cfg.Gateway.IsValid() {
		allow.Add(netip.PrefixFrom(cfg.Gateway, cfg.Gateway.BitLen()))
	}
	allow.Build()
	return &Engine{
		cfg:      cfg,
		store:    store,
		notifier: notifier,
		blocker:  blocker,
		clock:    clock,
		log:      func(string, ...any) {},
		allow:    allow,
		cooldown: make(map[string]*cooldownState),
	}
}

// SetLogger installs a logging callback (optional).
func (e *Engine) SetLogger(f func(string, ...any)) { e.log = f }

// SetMuter installs the suppression rules after construction.
func (e *Engine) SetMuter(m *Muter) { e.cfg.Muter = m }

// SetAlreadyBlocked installs the already-blocked check after construction
// (the block watcher is wired later in startup than the engine). Must be
// called before the first packet flows; it is not synchronised.
func (e *Engine) SetAlreadyBlocked(f func(netip.Addr) bool) { e.cfg.AlreadyBlocked = f }

// Apply swaps the runtime-editable policy settings — enforcement, cooldown,
// block TTL, quiet hours and the allowlist — without a restart. The gateway
// stays protected regardless of what the new allowlist says.
func (e *Engine) Apply(enforcement Enforcement, cooldown, blockTTL time.Duration, quiet QuietHours, allowlist []netip.Prefix) {
	allow := netset.New()
	for _, p := range allowlist {
		allow.Add(p)
	}
	if e.cfg.Gateway.IsValid() {
		allow.Add(netip.PrefixFrom(e.cfg.Gateway, e.cfg.Gateway.BitLen()))
	}
	allow.Build()

	e.mu.Lock()
	e.cfg.Enforcement = enforcement
	e.cfg.Cooldown = cooldown
	e.cfg.BlockTTL = blockTTL
	e.cfg.QuietHours = quiet
	e.cfg.Allowlist = allowlist
	e.allow = allow
	e.mu.Unlock()
}

// Raise implements detect.Sink: it is the single entry point from every
// detector.
func (e *Engine) Raise(f detect.Finding) {
	e.handle(context.Background(), f)
}

func (e *Engine) handle(ctx context.Context, f detect.Finding) {
	// A source the firewall is already dropping needs no further alerts or
	// re-blocks; its ongoing attempts show up in the per-block counters.
	if e.cfg.AlreadyBlocked != nil && f.Source.IsValid() && e.cfg.AlreadyBlocked(f.Source) {
		return
	}

	now := e.clock()

	// Operator mute rules: no alert, no notification — but still evaluate
	// blocking below, because muting is about noise, not about protection.
	if e.cfg.Muter != nil && e.cfg.Muter.Muted(f.Detector, f.Source, int(f.Port), now) {
		e.maybeBlock(ctx, f)
		return
	}

	// Cooldown: at most one notification per (detector, source) per window.
	// Extra occurrences are counted and reported with the next one.
	key := f.Detector + "|" + f.Source.String()
	e.mu.Lock()
	cooldown, quiet := e.cfg.Cooldown, e.cfg.QuietHours
	cs := e.cooldown[key]
	if cs == nil {
		cs = &cooldownState{}
		e.cooldown[key] = cs
	}
	withinCooldown := !cs.lastNotified.IsZero() && now.Sub(cs.lastNotified) < cooldown
	if withinCooldown {
		cs.suppressed++
		e.mu.Unlock()
		// Still evaluate blocking: suppressing a notification must not
		// suppress protection.
		e.maybeBlock(ctx, f)
		return
	}
	count := 1 + cs.suppressed
	cs.suppressed = 0
	cs.lastNotified = now
	e.mu.Unlock()

	alert := model.Alert{
		Time:     now,
		Detector: f.Detector,
		Severity: f.Severity,
		Source:   f.Source,
		Title:    f.Title,
		Detail:   f.Detail,
		Count:    count,
	}

	stored, err := e.store.InsertAlert(ctx, alert)
	if err != nil {
		e.log("policy: storing alert failed: %v", err)
		stored = alert
	}
	if inc, ok := e.store.(Incidenter); ok && stored.ID > 0 {
		if _, err := inc.AttachToIncident(ctx, stored); err != nil {
			e.log("policy: grouping alert into an incident: %v", err)
		}
	}

	// Quiet hours gate notification, not recording or blocking.
	if shouldNotify(quiet, stored, now) {
		e.notifier.Notify(ctx, stored)
	}
	e.maybeBlock(ctx, f)
}

// maybeBlock applies a block when the detector suggested one, enforcement is
// on, and the source is not protected.
func (e *Engine) maybeBlock(ctx context.Context, f detect.Finding) {
	e.mu.Lock()
	enforcement, ttl := e.cfg.Enforcement, e.cfg.BlockTTL
	e.mu.Unlock()
	if !f.SuggestBlock || enforcement != Enforce {
		return
	}
	if !f.Source.IsValid() {
		return
	}
	if e.Protected(f.Source) {
		e.log("policy: refusing to block allowlisted/gateway address %s", f.Source)
		return
	}
	if e.blocker == nil {
		return
	}
	prefix := netip.PrefixFrom(f.Source, f.Source.BitLen())
	if err := e.blocker.Block(ctx, prefix, f.Detector+": "+f.Title, ttl); err != nil {
		e.log("policy: block %s failed: %v", f.Source, err)
	}
}

// Protected reports whether an address must never be blocked.
func (e *Engine) Protected(addr netip.Addr) bool {
	e.mu.Lock()
	allow := e.allow
	e.mu.Unlock()
	return allow.Contains(addr)
}

// ProtectedPrefixes returns the never-block set as prefixes: the operator's
// allowlist plus the gateway. The firewall service needs the same set to hold
// manual blocks to the same rule, and deriving it here rather than at the
// call site is what keeps the two from drifting apart.
func (e *Engine) ProtectedPrefixes() []netip.Prefix {
	e.mu.Lock()
	out := append([]netip.Prefix(nil), e.cfg.Allowlist...)
	gw := e.cfg.Gateway
	e.mu.Unlock()
	if gw.IsValid() {
		out = append(out, netip.PrefixFrom(gw, gw.BitLen()))
	}
	return out
}

// shouldNotify applies quiet hours: during the window only alerts at or above
// MinSeverity are delivered. Takes the settings by value so the caller can
// snapshot them under the lock.
func shouldNotify(q QuietHours, a model.Alert, now time.Time) bool {
	if !q.Enabled {
		return true
	}
	if !inWindow(now, q.From, q.To) {
		return true
	}
	return a.Severity.Rank() >= q.MinSeverity.Rank()
}

// inWindow reports whether now's clock time falls in [from, to), handling a
// window that crosses midnight.
func inWindow(now, from, to time.Time) bool {
	n := now.Hour()*60 + now.Minute()
	f := from.Hour()*60 + from.Minute()
	t := to.Hour()*60 + to.Minute()
	if f == t {
		return false
	}
	if f < t {
		return n >= f && n < t
	}
	// Crosses midnight, e.g. 23:00–07:00.
	return n >= f || n < t
}
