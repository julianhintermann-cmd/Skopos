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
	"sync/atomic"
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
	// Gateways are always protected from blocking (the last-resort safety so
	// Skopos can never lock you out of your own network).
	Gateways []netip.Addr
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

	// Findings arrive on the capture goroutine — the one reading frames off
	// the wire — and handling one writes to SQLite, posts to ntfy over HTTP
	// and talks to netlink. Doing that inline stalls packet capture for as
	// long as the slowest of them takes, which on a 15-second HTTP timeout is
	// long enough to lose a great deal of traffic, precisely while an attack
	// is in progress. The queue hands the work to a goroutine instead.
	queue   chan detect.Finding
	async   atomic.Bool
	dropped atomic.Uint64

	forgotten  atomic.Uint64 // cooldown entries reclaimed
	unreported atomic.Uint64 // occurrences those entries never got to report

	mu       sync.Mutex
	cooldown map[string]*cooldownState
}

// findingQueue is how many findings may be waiting for the worker. Generous
// enough that ordinary bursts never touch it, bounded because the alternative
// to dropping under a flood is blocking capture, and a monitor that stops
// seeing traffic is worse than one that misses a redundant alert about a
// source it has already reacted to.
const findingQueue = 1024

// maxCooldownSources bounds the cooldown map, at the same number
// internal/detect caps every detector's per-source state at, for the same
// reason: this process is expected to run for months, and a port-forwarded box
// meets a steady trickle of addresses it has never seen. Capping the detectors
// and then handing every one of their findings to an uncapped map one layer
// down did not fix that leak, it moved it.
const maxCooldownSources = 8192

// cooldownSweepEvery is how often the worker ages the map out. The worker
// already owns its goroutine and takes e.mu between findings rather than
// during one, so this never touches the packet path.
const cooldownSweepEvery = time.Minute

type cooldownState struct {
	lastNotified time.Time
	suppressed   int // occurrences counted since the last notification
}

// CooldownStats reports the size of the cooldown map and what bounding it has
// cost. Forgotten entries are ordinarily harmless — an entry past its window
// suppresses nothing — but a forgotten entry still holding suppressed
// occurrences takes their count with it, and an operator is entitled to see
// that number rather than infer it from an alert whose Count looks low.
type CooldownStats struct {
	Tracked    int
	Forgotten  uint64
	Unreported uint64
}

// cooldownShed is what one reclamation gave up, carried out of the locked
// section so the log call happens with e.mu back down.
type cooldownShed struct {
	forgotten  int
	unreported int
	reset      bool
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
	for _, gw := range cfg.Gateways {
		if gw.IsValid() {
			allow.Add(netip.PrefixFrom(gw, gw.BitLen()))
		}
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
		queue:    make(chan detect.Finding, findingQueue),
		cooldown: make(map[string]*cooldownState),
	}
}

// Run drains findings until ctx is cancelled. Until it is called the engine
// handles findings inline on the caller's goroutine, which is what tests want
// and what a caller that never starts a worker gets.
func (e *Engine) Run(ctx context.Context) {
	e.async.Store(true)
	defer e.async.Store(false)
	// Age the cooldown map from here rather than from handle: the sources that
	// need forgetting are precisely the ones that have stopped producing
	// findings, so nothing on the finding path would ever come back to them.
	sweep := time.NewTicker(cooldownSweepEvery)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-e.queue:
			e.handle(ctx, f)
		case <-sweep.C:
			e.mu.Lock()
			shed := e.ageCooldownLocked(e.clock())
			e.mu.Unlock()
			e.reportShed(shed)
		}
	}
}

// DroppedFindings counts findings discarded because the queue was full. It is
// reported as a metric rather than kept quiet: dropping them is the right
// trade against stalling capture, but it is still something the operator is
// entitled to know happened.
func (e *Engine) DroppedFindings() uint64 { return e.dropped.Load() }

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
	for _, gw := range e.cfg.Gateways {
		if gw.IsValid() {
			allow.Add(netip.PrefixFrom(gw, gw.BitLen()))
		}
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
// detector, and it is called from the packet path, so it must not block.
func (e *Engine) Raise(f detect.Finding) {
	if !e.async.Load() {
		e.handle(context.Background(), f)
		return
	}
	select {
	case e.queue <- f:
	default:
		if n := e.dropped.Add(1); n == 1 || n%100 == 0 {
			e.log("policy: finding queue full, dropped %d so far (%s from %s)", n, f.Detector, f.Source)
		}
	}
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
	var shed cooldownShed
	if cs == nil {
		// The map is about to take an entry it has no other way of losing.
		// Reclaiming here as well as from the worker is what covers the two
		// stretches where the worker is not running: before Run starts and
		// after it returns at shutdown, when Raise handles findings inline.
		if len(e.cooldown) >= maxCooldownSources {
			shed = e.reclaimCooldownLocked(now)
		}
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
	e.reportShed(shed)

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

// ageCooldownLocked forgets cooldown state for sources that have been quiet
// long enough that their next finding would notify anyway. Callers hold e.mu.
func (e *Engine) ageCooldownLocked(now time.Time) cooldownShed {
	// Two cooldowns of silence. One is enough for the entry to stop
	// suppressing anything; the second is the margin that keeps a source
	// alternating around the window from losing its aggregation count.
	idle := 2 * e.cfg.Cooldown
	if idle < cooldownSweepEvery {
		idle = cooldownSweepEvery
	}
	var shed cooldownShed
	for key, cs := range e.cooldown {
		if now.Sub(cs.lastNotified) < idle {
			continue
		}
		shed.forgotten++
		shed.unreported += cs.suppressed
		delete(e.cooldown, key)
	}
	e.forgotten.Add(uint64(shed.forgotten))
	e.unreported.Add(uint64(shed.unreported))
	return shed
}

// reclaimCooldownLocked makes room in a full map. Callers hold e.mu.
//
// Ageing comes first, so in the ordinary case only entries that have stopped
// meaning anything are lost. If that cannot get the map under half the cap —
// more than four thousand distinct sources all inside their cooldown window,
// which is a distributed scan and not a Tuesday — the map goes entirely. The
// alternative to dropping it is refusing new entries, and a source with no
// cooldown state notifies on every single finding, which is a worse flood than
// the one extra notification per tracked source that a reset costs. Either way
// the next reclamation is thousands of insertions away, so this stays off the
// per-finding cost.
func (e *Engine) reclaimCooldownLocked(now time.Time) cooldownShed {
	shed := e.ageCooldownLocked(now)
	if len(e.cooldown) <= maxCooldownSources/2 {
		return shed
	}
	dropped, unreported := len(e.cooldown), 0
	for _, cs := range e.cooldown {
		unreported += cs.suppressed
	}
	shed.forgotten += dropped
	shed.unreported += unreported
	e.forgotten.Add(uint64(dropped))
	e.unreported.Add(uint64(unreported))
	e.cooldown = make(map[string]*cooldownState, maxCooldownSources)
	shed.reset = true
	return shed
}

// reportShed logs a reclamation. Called with e.mu down, because the logger
// writes to the process log and holding the engine's mutex across that would
// put file I/O in front of every finding.
func (e *Engine) reportShed(shed cooldownShed) {
	if !shed.reset && shed.unreported == 0 {
		// Ordinary ageing of entries that had nothing left to say. The
		// counters carry it; the log does not need to.
		return
	}
	if shed.reset {
		e.log("policy: cooldown map overrun at %d sources, dropped all of it — %d suppressed occurrences unreported, and each tracked source may notify once more",
			maxCooldownSources, shed.unreported)
		return
	}
	e.log("policy: forgot %d quiet cooldown entries, %d suppressed occurrences never reported",
		shed.forgotten, shed.unreported)
}

// CooldownStats reports the cooldown map's size and what bounding it has cost.
func (e *Engine) CooldownStats() CooldownStats {
	e.mu.Lock()
	tracked := len(e.cooldown)
	e.mu.Unlock()
	return CooldownStats{
		Tracked:    tracked,
		Forgotten:  e.forgotten.Load(),
		Unreported: e.unreported.Load(),
	}
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
	gateways := append([]netip.Addr(nil), e.cfg.Gateways...)
	e.mu.Unlock()
	for _, gw := range gateways {
		if gw.IsValid() {
			out = append(out, netip.PrefixFrom(gw, gw.BitLen()))
		}
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
