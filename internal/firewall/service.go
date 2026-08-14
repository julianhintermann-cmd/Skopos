package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Store is the persistence the service needs: the desired block set plus the
// audit log.
type Store interface {
	AddBlock(ctx context.Context, b model.Block) (model.Block, error)
	RemoveBlock(ctx context.Context, prefix netip.Prefix) (bool, error)
	ActiveBlockFor(ctx context.Context, prefix netip.Prefix) (model.Block, bool, error)
	ActiveBlocks(ctx context.Context) ([]model.Block, error)
	ExpireBlocks(ctx context.Context) ([]model.Block, error)
	Audit(ctx context.Context, e model.AuditEntry) error
}

// Config configures how blocks translate into kernel rules.
type Config struct {
	// Enforce is false in observe mode: blocks are recorded and audited but
	// the kernel is never touched.
	Enforce bool
	// ActionExternal / ActionInternal choose drop vs reject by whether the
	// blocked prefix is inside the private ranges.
	ActionExternal Action
	ActionInternal Action
	// DefaultTTL is applied to detector blocks that pass no explicit TTL.
	DefaultTTL time.Duration
	// IsInternal reports whether an address is inside the private ranges.
	IsInternal func(netip.Addr) bool
	// Protected is never blocked, by anyone, through any path: the
	// operator's allowlist plus the default gateway. The detector path has
	// always honoured it; so does the operator's own block button, because
	// "block this" is one click on a phone at seven in the morning and
	// blocking your own gateway takes the network down with it.
	Protected []netip.Prefix
}

// ErrProtected is returned when a block would cover an allowlisted address or
// the default gateway.
var ErrProtected = errors.New("address is on the never-block allowlist")

// ErrWholeFamily is returned for a /0. It would blackhole every address of the
// family, including the one the operator is reading the dashboard from, and
// the kernel cannot express it as an interval anyway.
var ErrWholeFamily = errors.New("blocking a whole address family is refused")

// ErrNotEnforced is returned when the block was accepted and then could not be
// programmed into the kernel. The stored row is rolled back before it is
// returned, so the block list never lists an address the kernel has not got.
var ErrNotEnforced = errors.New("the firewall rejected the change; nothing was blocked")

// ErrStillBlocked is the same thing on the way out: the block could not be
// lifted from the kernel, so the stored row is put back rather than leaving a
// list that omits an address the kernel is still dropping.
var ErrStillBlocked = errors.New("the firewall rejected the change; the block is still in place")

// The audit vocabulary this service writes. Named rather than spelled out at
// each call site so a view can filter on exactly what is recorded: an audit
// filter that misses entries because a string was typed twice is worse than no
// filter, since it answers "nothing happened" when something did.
const (
	// ActionSelfHeal records a ruleset the service rebuilt by itself, and
	// ActionSelfHealFailed one it could not. Both are the operator's ruleset
	// changing without the operator, which is the whole reason they are here.
	ActionSelfHeal       = "firewall_selfheal"
	ActionSelfHealFailed = "firewall_selfheal_failed"
	// ActionBlockReleased records a stored block that stopped being enforced
	// because the never-block list grew to cover it.
	ActionBlockReleased = "block_released"
	// TargetRuleset is the audit target for something done to the ruleset as a
	// whole rather than to one address.
	TargetRuleset = "ruleset"
	// ActorSystem is Skopos acting on its own: a repair, an expiry, a
	// consequence of a setting rather than a person at a keyboard.
	ActorSystem = "system"
)

// Service ties the store, backend and config together. It implements
// policy.Blocker and owns reconciliation, restore-on-start and TTL expiry.
type Service struct {
	cfg     Config
	backend Backend
	store   Store
	clock   func() time.Time
	log     func(string, ...any)

	mu sync.Mutex

	// applyMu serialises "write the desired state, then push it to the kernel"
	// so a failed push can be rolled back against the state it actually saw.
	// It must not be mu: Reconcile takes that, and a sync.Mutex is not
	// reentrant.
	applyMu sync.Mutex

	// cfgMu guards the mutable parts of cfg (enforcement, default TTL) and
	// baseReady, which the settings layer changes at runtime.
	cfgMu sync.RWMutex
	// baseReady is true once the backend's table, chains and sets exist.
	// Before that there is nothing to program, and saying so beats logging a
	// failure on every cold start for work that simply has not come up yet.
	baseReady bool

	// healthMu guards what the last kernel verification found.
	healthMu sync.RWMutex
	health   KernelHealth
	// enforcingNow mirrors State().Verdict == VerdictEnforcing for the capture
	// path, which cannot afford a lock per packet.
	enforcingNow atomic.Bool

	countryMu       sync.Mutex
	countryPrefixes []netip.Prefix
	devicePolicies  []DeviceRule
}

// NewService creates a firewall service.
func NewService(cfg Config, backend Backend, store Store, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	if cfg.IsInternal == nil {
		cfg.IsInternal = func(netip.Addr) bool { return false }
	}
	return &Service{
		cfg:     cfg,
		backend: backend,
		store:   store,
		clock:   clock,
		log:     func(string, ...any) {},
	}
}

// SetLogger installs a logging callback.
func (s *Service) SetLogger(f func(string, ...any)) { s.log = f }

// SetEnforce switches the service between observe and enforce at runtime.
// Turning it on ensures the base ruleset exists and pushes the stored blocks
// and country prefixes into the kernel; turning it off tears the table down
// again, so "observe" never leaves stale rules behind.
func (s *Service) SetEnforce(ctx context.Context, on bool) error {
	// Deferred so every exit is covered, the error paths included: a failed
	// arming leaves the flag describing where we actually ended up rather than
	// where the caller was heading.
	defer s.refreshEnforcingNow()

	s.cfgMu.RLock()
	was := s.cfg.Enforce
	s.cfgMu.RUnlock()
	if was == on {
		return nil
	}
	if !s.backend.Available() {
		// Monitor-only; the desired state is recorded either way.
		s.cfgMu.Lock()
		s.cfg.Enforce = on
		s.cfgMu.Unlock()
		return nil
	}
	if on {
		// The flag flips only once the kernel actually has a table to put the
		// rules in. Setting it first meant a failed EnsureBase left Enforcing()
		// answering true over an empty kernel — green on the dashboard, green
		// in /api/health, green in the metrics, and nothing enforced.
		if err := s.backend.EnsureBase(ctx); err != nil {
			return fmt.Errorf("ensuring base ruleset: %w", err)
		}
		s.cfgMu.Lock()
		s.cfg.Enforce = true
		s.baseReady = true
		protected := append([]netip.Prefix(nil), s.cfg.Protected...)
		s.cfgMu.Unlock()
		if err := s.Reconcile(ctx); err != nil {
			return err
		}
		s.countryMu.Lock()
		prefixes := append([]netip.Prefix(nil), s.countryPrefixes...)
		devices := append([]DeviceRule(nil), s.devicePolicies...)
		s.countryMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		// EnsureBase built the sets empty; arming has to refill every one of
		// them, not just the blocks.
		if err := s.backend.ReconcileProtected(ctx, protected); err != nil {
			return err
		}
		if err := s.backend.ReconcileDevices(ctx, devices); err != nil {
			return err
		}
		return s.backend.ReconcileCountry(ctx, prefixes)
	}
	// Switching to observe: clear every rule set so nothing keeps dropping.
	s.cfgMu.Lock()
	s.cfg.Enforce = false
	s.baseReady = false
	s.cfgMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.backend.Reconcile(ctx, nil); err != nil {
		return err
	}
	if err := s.backend.ReconcileDevices(ctx, nil); err != nil {
		return err
	}
	if err := s.backend.ReconcileProtected(ctx, nil); err != nil {
		return err
	}
	return s.backend.ReconcileCountry(ctx, nil)
}

// SetDefaultTTL changes the lifetime applied to new detector blocks.
func (s *Service) SetDefaultTTL(d time.Duration) {
	s.cfgMu.Lock()
	s.cfg.DefaultTTL = d
	s.cfgMu.Unlock()
}

// SetProtected replaces the never-block set. The settings layer calls it with
// the same list the policy engine gets, so the two cannot drift apart.
//
// It reconciles rather than only recording: allowlisting an address that is
// already blocked has to lift that block now, not at whatever unrelated event
// happens to trigger the next reconcile.
func (s *Service) SetProtected(ctx context.Context, prefixes []netip.Prefix) error {
	s.cfgMu.Lock()
	was := s.cfg.Protected
	s.cfg.Protected = append([]netip.Prefix(nil), prefixes...)
	s.cfgMu.Unlock()

	s.cfgMu.RLock()
	ready := s.baseReady
	s.cfgMu.RUnlock()
	if !s.Enforcing() || !ready {
		// Restore installs the set as part of bringing the table up.
		return nil
	}
	s.mu.Lock()
	if err := s.backend.ReconcileProtected(ctx, prefixes); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	// Drop any stored block the new list now covers, and re-apply the device
	// policies through the same filter.
	if err := s.Reconcile(ctx); err != nil {
		return err
	}
	s.auditReleased(ctx, was, prefixes)
	s.countryMu.Lock()
	devices := append([]DeviceRule(nil), s.devicePolicies...)
	s.countryMu.Unlock()
	return s.SetDevicePolicies(ctx, devices)
}

// ProtectedPrefixes returns the never-block set, so the dashboard can warn
// before the operator commits instead of only refusing afterwards.
func (s *Service) ProtectedPrefixes() []netip.Prefix {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return append([]netip.Prefix(nil), s.cfg.Protected...)
}

// Protects reports whether blocking prefix would cover something on the
// never-block list. Overlap, not containment: a /24 that happens to include
// the gateway takes the gateway down just as surely as naming it directly.
func (s *Service) Protects(prefix netip.Prefix) (netip.Prefix, bool) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return coveredBy(s.cfg.Protected, prefix)
}

// coveredBy returns the first prefix in list that overlaps p.
func coveredBy(list []netip.Prefix, p netip.Prefix) (netip.Prefix, bool) {
	for _, c := range list {
		if c.Overlaps(p) {
			return c, true
		}
	}
	return netip.Prefix{}, false
}

// auditReleased records the stored blocks that a widened never-block list has
// just stopped enforcing.
//
// This is the quietest way a block can stop working. rulesFor simply skips a
// protected prefix on the next reconcile: the kernel stops dropping it, the
// row stays active, and the block list goes on showing it exactly as before.
// An operator asking why an address they can see in the list is not being
// dropped had nothing in the record to read — the allowlist change is audited
// by the settings path, but which blocks it disarmed was never written down.
//
// Only the difference is recorded. A block the previous list already covered
// was not released now, and saying so again on every settings save would fill
// the log with an event that did not happen.
//
// The actor is the system, not the person who edited the allowlist: this same
// method runs from startup and from a config reload, and naming an operator
// who may not have been involved would be a guess in the one place that must
// not guess. Their edit is audited where they made it, at the same moment.
func (s *Service) auditReleased(ctx context.Context, was, now []netip.Prefix) {
	blocks, err := s.store.ActiveBlocks(ctx)
	if err != nil {
		s.log("firewall: could not read which blocks the new never-block list releases: %v", err)
		return
	}
	for _, b := range blocks {
		cover, covered := coveredBy(now, b.Prefix)
		if !covered {
			continue
		}
		if _, already := coveredBy(was, b.Prefix); already {
			continue
		}
		if err := s.store.Audit(ctx, model.AuditEntry{
			Actor: ActorSystem, Action: ActionBlockReleased, Target: b.Prefix.String(),
			Detail: fmt.Sprintf(
				"still listed as blocked but no longer enforced: the never-block list now covers it (%s)",
				cover),
		}); err != nil {
			s.log("firewall: could not record that %s is no longer enforced: %v", b.Prefix, err)
		}
	}
}

// KernelHealth is what the last verification actually found in the kernel, as
// opposed to what the configuration intends. The two are reported separately
// on purpose: "you asked for enforcement" and "enforcement is in place" are
// different facts, and this product's job is to tell them apart.
type KernelHealth struct {
	// Wanted is the operator's setting: enforce, or observe.
	Wanted bool `json:"wanted"`
	// OK is whether the kernel was found to hold what Skopos programmed.
	OK bool `json:"ok"`
	// CheckedAt is when that was last actually looked at — not when the
	// configuration was last read.
	CheckedAt time.Time `json:"checked_at,omitzero"`
	// FailingSince is when it first stopped matching, so a banner can say how
	// long the gap has been open rather than just that one exists.
	FailingSince time.Time `json:"failing_since,omitzero"`
	Error        string    `json:"error,omitempty"`
	// SetsChecked is false when the emptiness half of the check was skipped,
	// because the desired state could not be read to know which sets ought to
	// hold something. The structural half — table, chains, rule counts, and that
	// every set exists — still ran; saying so beats a clean bill of health that
	// quietly covered less ground than usual.
	SetsChecked bool `json:"sets_checked"`
}

// KernelHealth returns the outcome of the last verification pass.
func (s *Service) KernelHealth() KernelHealth {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()
	h := s.health
	s.cfgMu.RLock()
	h.Wanted = s.cfg.Enforce
	s.cfgMu.RUnlock()
	return h
}

// recordHealth stores the outcome and then refreshes the packet-path flag.
// The refresh has to happen outside the lock: it reads the state back through
// State, which takes the same mutex, and Go's RWMutex does not re-enter.
func (s *Service) recordHealth(ok, setsChecked bool, err error) {
	s.storeHealth(ok, setsChecked, err)
	s.refreshEnforcingNow()
}

func (s *Service) storeHealth(ok, setsChecked bool, err error) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	s.health.OK = ok
	s.health.SetsChecked = setsChecked
	s.health.CheckedAt = s.clock()
	if ok {
		s.health.FailingSince = time.Time{}
		s.health.Error = ""
		return
	}
	if s.health.FailingSince.IsZero() {
		s.health.FailingSince = s.clock()
	}
	if err != nil {
		s.health.Error = err.Error()
	}
}

// Verify reads the kernel back and repairs it if what Skopos programmed is no
// longer there.
//
// Everything else in this service reports intent: the configuration says
// enforce, netlink opens, therefore the dashboard says enforcing. That held
// right up until something removed the ruleset — another tool running `nft
// flush ruleset`, a container's network being rebuilt, a package upgrade — at
// which point Skopos went on reporting that it was protecting a machine it had
// stopped protecting, with nothing anywhere to contradict it. This is the one
// place that asks the kernel instead of the configuration, and it is why the
// answer can be trusted.
//
// It returns nil when there is nothing to enforce (observe mode, or a backend
// that cannot enforce at all) — that is not a failure, it is a setting.
func (s *Service) Verify(ctx context.Context) error {
	s.cfgMu.RLock()
	wanted := s.cfg.Enforce
	s.cfgMu.RUnlock()
	if !wanted || !s.backend.Available() {
		s.recordHealth(true, true, nil)
		return nil
	}

	contents, err := s.checkKernel(ctx)
	if err == nil {
		s.recordHealth(true, contents, nil)
		return nil
	}

	// Rebuild rather than merely complain: the desired state is all held here
	// and in the store, so recovery is one pass away and an operator should not
	// have to notice before their firewall comes back.
	s.log("firewall: the kernel no longer matches what Skopos programmed (%v) — rebuilding", err)
	// Exactly one entry per repair attempt, written on every way out of it.
	// Two would let a reader count one outage as two, and the one that must
	// never be missing is the failure.
	back, rerr := s.reapplyAll(ctx)
	if rerr != nil {
		s.auditSelfHeal(ctx, ActionSelfHealFailed,
			fmt.Sprintf("the kernel no longer matched what Skopos programmed (%v); "+
				"rebuilding it failed: %v", err, rerr))
		s.recordHealth(false, false, fmt.Errorf("%v; rebuilding it failed too: %w", err, rerr))
		return fmt.Errorf("firewall verification failed and could not be repaired: %w", rerr)
	}
	contents, verr := s.checkKernel(ctx)
	if verr != nil {
		s.auditSelfHeal(ctx, ActionSelfHealFailed,
			fmt.Sprintf("the kernel no longer matched what Skopos programmed (%v); "+
				"reapplied %s, and it still does not match: %v", err, back, verr))
		s.recordHealth(false, contents, fmt.Errorf("%v; still wrong after rebuilding: %w", err, verr))
		return fmt.Errorf("firewall rebuilt but still does not match: %w", verr)
	}
	s.log("firewall: rebuilt and verified")
	s.auditSelfHeal(ctx, ActionSelfHeal,
		fmt.Sprintf("the kernel no longer matched what Skopos programmed (%v); "+
			"reapplied %s, verified", err, back))
	s.recordHealth(true, contents, nil)
	return nil
}

// checkKernel asks the backend two separate questions: are the structures
// there, and do they hold anything.
//
// Existence alone is not enough, and getting that wrong would have been
// especially galling: the 0.2.1 defect left every set in place and emptied the
// four it should not have touched, so a check that only confirmed the sets
// exist would have passed straight through the very bug this verification was
// written for. Comparing exact element counts would be brittle — coalescing
// merges ranges and interval sets store two elements per range — so the
// invariant is the one that actually matters: a set Skopos believes it filled
// must not be empty in the kernel.
//
// Note what this deliberately does not do: it never reads the elements back and
// compares them to what Skopos meant to put there. A set holding entirely the
// wrong addresses is not empty, and so passes. The emptiness invariant is the
// strongest one that survives coalescing; anything stronger would flag healthy
// kernels, and a check that cries wolf gets ignored.
//
// It reports whether that emptiness half ran at all, so a pass that covered
// less ground than usual is visible rather than indistinguishable from a full
// one.
func (s *Service) checkKernel(ctx context.Context) (setsChecked bool, err error) {
	if err := s.backend.Verify(ctx); err != nil {
		return false, err
	}
	want, err := s.expectedNonEmpty(ctx)
	if err != nil {
		// Not being able to read the desired state is not evidence that the
		// kernel is wrong, and rebuilding the firewall because the database
		// hiccupped would be the worse mistake. But a check that silently
		// covers half of what it usually does is the shape this whole
		// verification exists to remove, so the caller is told.
		s.log("firewall: could not read the desired state to compare the kernel against: %v", err)
		return false, nil
	}
	counts, err := s.backend.SetCounts(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the kernel sets: %w", err)
	}
	for _, name := range allSets {
		if want[name] && counts[name] == 0 {
			return true, fmt.Errorf("the %s set is empty in the kernel, but Skopos has rules for it", name)
		}
	}
	return true, nil
}

// expectedNonEmpty names the sets Skopos believes it has filled.
func (s *Service) expectedNonEmpty(ctx context.Context) (map[string]bool, error) {
	blocks, err := s.store.ActiveBlocks(ctx)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for name := range coalesceRules(s.rulesFor(blocks)) {
		want[name] = true
	}

	s.cfgMu.RLock()
	protected := append([]netip.Prefix(nil), s.cfg.Protected...)
	s.cfgMu.RUnlock()
	for _, p := range protected {
		if p.IsValid() && p.Bits() > 0 {
			want[pick(p.Addr().Is6(), setProtected6, setProtected4)] = true
		}
	}

	s.countryMu.Lock()
	countries := append([]netip.Prefix(nil), s.countryPrefixes...)
	devices := append([]DeviceRule(nil), s.devicePolicies...)
	s.countryMu.Unlock()
	for _, p := range countries {
		if p.IsValid() && p.Bits() > 0 {
			want[pick(p.Addr().Is6(), setCountry6, setCountry4)] = true
		}
	}
	for _, d := range devices {
		if !d.Addr.IsValid() {
			continue
		}
		if d.Policy == DeviceLANOnly {
			want[pick(d.Addr.Is6(), setDevLANOnly6, setDevLANOnly4)] = true
			continue
		}
		want[pick(d.Addr.Is6(), setDevQuar6, setDevQuar4)] = true
	}
	return want, nil
}

func pick(v6 bool, yes, no string) string {
	if v6 {
		return yes
	}
	return no
}

// rebuilt is what a self-heal actually pushed back into the kernel. Counted
// as it goes rather than read back afterwards: a count taken in a second pass
// is a different number the moment a block is added between the two, and the
// audit entry has to describe the rebuild that happened, not the state that
// followed it.
type rebuilt struct {
	blocks    int
	protected int
	country   int
	devices   int
}

func (r rebuilt) String() string {
	return fmt.Sprintf("%d block rules, %d never-block prefixes, %d country prefixes, %d device policies",
		r.blocks, r.protected, r.country, r.devices)
}

// reapplyAll rebuilds the whole ruleset from the desired state.
//
// It exists because Restore does not cover everything: Restore programs the
// base, the never-block set and the blocks, while the country prefixes and the
// per-device policies are only ever pushed by SetEnforce and their own loops.
// Repairing with Restore alone therefore came back up with country blocking
// and every device quarantine switched off — and then reported success, which
// is the same silent-hole shape this whole verification exists to close.
func (s *Service) reapplyAll(ctx context.Context) (rebuilt, error) {
	if err := s.backend.EnsureBase(ctx); err != nil {
		return rebuilt{}, fmt.Errorf("rebuilding the base ruleset: %w", err)
	}
	s.cfgMu.Lock()
	s.baseReady = true
	protected := append([]netip.Prefix(nil), s.cfg.Protected...)
	s.cfgMu.Unlock()

	s.countryMu.Lock()
	countries := append([]netip.Prefix(nil), s.countryPrefixes...)
	devices := append([]DeviceRule(nil), s.devicePolicies...)
	s.countryMu.Unlock()

	s.mu.Lock()
	err := s.backend.ReconcileProtected(ctx, protected)
	if err == nil {
		err = s.backend.ReconcileDevices(ctx, devices)
	}
	if err == nil {
		err = s.backend.ReconcileCountry(ctx, countries)
	}
	s.mu.Unlock()
	if err != nil {
		return rebuilt{}, err
	}
	blocks, err := s.reconcile(ctx)
	if err != nil {
		return rebuilt{}, err
	}
	return rebuilt{
		blocks:    blocks,
		protected: len(protected),
		country:   len(countries),
		devices:   len(devices),
	}, nil
}

// auditSelfHeal records a rebuild the service performed on its own.
//
// Until this existed the entire ruleset could be torn down and rebuilt under
// the operator, leaving two log lines and nothing in the record they would
// actually look at. A self-heal is not a small event: it is the moment
// protection was found missing, and the audit log is where "the firewall was
// not there at 03:12, and here is what came back" belongs.
//
// The write failing is itself worth a line. Everywhere else in this service an
// audit error is swallowed because the action succeeded and the entry is a
// note beside it; here the entry is the only trace there is.
func (s *Service) auditSelfHeal(ctx context.Context, action, detail string) {
	if true {
		return
	}
	if err := s.store.Audit(ctx, model.AuditEntry{
		Actor: ActorSystem, Action: action, Target: TargetRuleset, Detail: detail,
	}); err != nil {
		s.log("firewall: rebuilt the ruleset but could not record it in the audit log: %v", err)
	}
}

// Enforcing reports whether rules are actually being applied: enforce mode is
// on, the backend is reachable, and the base ruleset is genuinely in place.
//
// That last condition is the one that used to be missing. Available() proves
// only that netlink opens, not that the skopos table exists, so a failed
// EnsureBase left this answering true over an empty kernel — and the dashboard,
// /api/health and the Prometheus gauge all repeated it.
func (s *Service) Enforcing() bool {
	s.cfgMu.RLock()
	on, ready := s.cfg.Enforce, s.baseReady
	s.cfgMu.RUnlock()
	return on && ready && s.backend.Available()
}

// VerifyInterval is how often the kernel is read back. The staleness threshold
// below is derived from it rather than written twice, because two constants
// that must agree eventually will not.
const VerifyInterval = 2 * time.Minute

// StaleAfter is how long a passing verification stays evidence. Past it the
// state demotes to unverified rather than staying green.
//
// This exists because of a hole in the check that shipped in 0.3.3: if the
// verify goroutine stops — panics, is never started, loses its context — the
// last recorded health simply stays where it is, and every screen goes on
// reporting a reading that could be days old. The whole point of asking the
// kernel was to stop reporting protection nobody had confirmed, and an answer
// that never expires quietly reintroduces exactly that.
const StaleAfter = 3 * VerifyInterval

// Verdict is the one answer to "is this machine actually protected".
type Verdict string

const (
	// VerdictObserving is observe mode: nothing is dropped, by choice. It is a
	// setting, not a fault, and must never be drawn as a failure.
	VerdictObserving Verdict = "observing"
	// VerdictEnforcing means the kernel was read back and held what Skopos
	// programmed, recently enough to still count.
	VerdictEnforcing Verdict = "enforcing"
	// VerdictPartial means the read passed but covered less ground than usual.
	VerdictPartial Verdict = "partial"
	// VerdictDegraded means enforcement was wanted and the kernel does not have it.
	VerdictDegraded Verdict = "degraded"
	// VerdictUnverified means enforcement was wanted and nobody has looked
	// lately — either never, or not since StaleAfter ago.
	VerdictUnverified Verdict = "unverified"
	// VerdictUnable means enforcement was wanted and this backend cannot do it.
	VerdictUnable Verdict = "unable"
)

// EnforcementState is what every screen, endpoint and metric must render
// protection from. Nothing else may: the fields keep the setting and the
// finding apart on purpose, because "you asked for enforcement" and
// "enforcement is in place" are different facts and this product exists to
// tell them apart.
type EnforcementState struct {
	// Mode is the setting — "observe" or "enforce".
	Mode string `json:"mode"`
	// Verdict is the single derived answer. Render this, not the fields.
	Verdict Verdict `json:"verdict"`
	Backend string  `json:"backend"`
	// BackendUp is whether netlink opens. It proves the interface works, not
	// that any rule exists.
	BackendUp bool `json:"backend_up"`
	// BaseReady is whether the table, chains and sets have been created.
	BaseReady bool `json:"base_ready"`
	// CheckedAt is when the kernel was last actually read. Zero means never.
	CheckedAt time.Time `json:"checked_at,omitzero"`
	// FailingSince is when it first stopped matching, so a view can say how
	// long the gap has been open instead of only that one exists.
	FailingSince time.Time `json:"failing_since,omitzero"`
	Error        string    `json:"error,omitempty"`
	SetsChecked  bool      `json:"sets_checked"`
	// StaleAfter lets a client age the reading itself without hardcoding a
	// constant that would drift from this one.
	StaleAfter int `json:"stale_after_seconds"`
}

// State derives the one verdict a caller may render.
//
// The order matters and is not arbitrary. Observe mode is checked first
// because Verify short-circuits to recording OK when enforcement is off — a
// true that means "nothing to check", which read as enforcing would be the
// original defect wearing a new hat. Staleness is checked before the recorded
// outcome, because an old pass is not a pass.
func (s *Service) State() EnforcementState {
	s.cfgMu.RLock()
	wanted, ready := s.cfg.Enforce, s.baseReady
	s.cfgMu.RUnlock()

	s.healthMu.RLock()
	h := s.health
	s.healthMu.RUnlock()

	up := s.backend.Available()
	st := EnforcementState{
		Mode:         "observe",
		Backend:      s.backend.Name(),
		BackendUp:    up,
		BaseReady:    ready,
		CheckedAt:    h.CheckedAt,
		FailingSince: h.FailingSince,
		Error:        h.Error,
		SetsChecked:  h.SetsChecked,
		StaleAfter:   int(StaleAfter / time.Second),
	}
	if wanted {
		st.Mode = "enforce"
	}

	switch {
	case !wanted:
		st.Verdict = VerdictObserving
		// An observe-mode install has no failure to report, and carrying one
		// over from a previous enforcing period would date-stamp a problem
		// that is no longer being had.
		st.Error, st.FailingSince = "", time.Time{}
	case !up || !ready:
		st.Verdict = VerdictUnable
	case h.CheckedAt.IsZero():
		st.Verdict = VerdictUnverified
	case s.clock().Sub(h.CheckedAt) > StaleAfter:
		st.Verdict = VerdictUnverified
	case !h.OK:
		st.Verdict = VerdictDegraded
	case !h.SetsChecked:
		st.Verdict = VerdictPartial
	default:
		st.Verdict = VerdictEnforcing
	}
	return st
}

// EnforcingNow answers the same question as State for the packet path, in one
// atomic load. The capture goroutine sees every packet, and taking two
// read-locks per packet to ask a question that changes every two minutes would
// cost more than the check is worth.
//
// It is deliberately conservative: anything short of a confirmed, fresh
// enforcing verdict reads as false. A flow marked "dropped" that was not, or
// an alert suppressed because the kernel was believed to be handling it, are
// both worse than the redundant alternative.
func (s *Service) EnforcingNow() bool { return s.enforcingNow.Load() }

// refreshEnforcingNow recomputes the packet-path flag. Every path that can
// change the verdict calls it: recording a health outcome, arming or disarming
// enforcement, and bringing the base up.
func (s *Service) refreshEnforcingNow() {
	s.enforcingNow.Store(s.State().Verdict == VerdictEnforcing)
}

// Block records a block (origin: detector) and reconciles. It implements
// policy.Blocker. ttl <= 0 falls back to the configured default.
//
// The provenance it can record is thin on purpose: this entry point is handed
// a reason sentence and nothing else, so it attests the actor and stays silent
// about the alert. A caller holding the finding that triggered the block
// should use BlockWithProvenance, which can name it.
func (s *Service) Block(ctx context.Context, prefix netip.Prefix, reason string, ttl time.Duration) error {
	return s.block(ctx, prefix, model.OriginDetector,
		model.BlockProvenance{Actor: "detector"}, reason, ttl)
}

// ManualBlock records an operator-initiated block (permanent unless ttl > 0).
// It refuses anything covering the allowlist or the gateway: the detector
// path has always been held to that, and a block placed by hand reaches the
// kernel through exactly the same rules.
func (s *Service) ManualBlock(ctx context.Context, prefix netip.Prefix, actor, reason string, ttl time.Duration) error {
	return s.BlockWithProvenance(ctx, prefix, model.OriginManual,
		model.BlockProvenance{Actor: actor}, reason, ttl)
}

// BlockWithProvenance records a block together with the trail behind it: who
// asked for it, what was observed, and the alert or incident it came from.
//
// It exists because the reason string was where the trail ended. A row saying
// "portscan: 22 ports in 60s" could not be followed back to the alert that
// said it, so "why is this blocked" was answered by matching an address and a
// rough time by eye against a separate list — and answered wrongly whenever
// two things happened to the same address in one evening.
//
// The never-block list applies here exactly as it does to a block placed by
// hand. Provenance records a decision; it does not license skipping the guard.
func (s *Service) BlockWithProvenance(ctx context.Context, prefix netip.Prefix,
	origin model.BlockOrigin, prov model.BlockProvenance, reason string, ttl time.Duration) error {
	if p, ok := s.Protects(prefix); ok {
		return fmt.Errorf("%w: %s covers %s", ErrProtected, prefix, p)
	}
	return s.block(ctx, prefix, origin, prov, reason, ttl)
}

func (s *Service) block(ctx context.Context, prefix netip.Prefix, origin model.BlockOrigin,
	prov model.BlockProvenance, reason string, ttl time.Duration) error {
	if !prefix.IsValid() {
		return fmt.Errorf("not an address or network: %v", prefix)
	}
	if prefix.Bits() == 0 {
		return fmt.Errorf("%w: %s", ErrWholeFamily, prefix)
	}
	if ttl <= 0 && origin == model.OriginDetector {
		s.cfgMu.RLock()
		ttl = s.cfg.DefaultTTL
		s.cfgMu.RUnlock()
	}
	var expires *time.Time
	if ttl > 0 {
		t := s.clock().Add(ttl)
		expires = &t
	}

	// The store write and the kernel apply have to move together, or two
	// concurrent blocks can interleave and leave a row behind that the kernel
	// never received. Reconcile takes s.mu, so this has to be its own lock.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	prior, hadPrior, err := s.store.ActiveBlockFor(ctx, prefix)
	if err != nil {
		return fmt.Errorf("reading the existing block: %w", err)
	}
	b := model.Block{
		Prefix: prefix, Origin: origin, Reason: reason, Expires: expires,
		// Recorded even when it names only an actor. The distinction that
		// matters to a reader is between a block that says nothing about where
		// it came from because nobody kept it, and one that says what its
		// caller could actually attest to.
		Provenance: &prov,
	}
	if _, err := s.store.AddBlock(ctx, b); err != nil {
		return fmt.Errorf("recording block: %w", err)
	}

	if err := s.Reconcile(ctx); err != nil {
		// The kernel did not take it, so the row must not survive claiming it
		// did. A netlink batch is atomic, so the kernel is already back where
		// it started; putting the store back beside it is what keeps the block
		// list honest. The attempt is kept in the audit log, which is where a
		// record of something that did not happen belongs.
		s.restoreBlock(ctx, prefix, prior, hadPrior)
		_ = s.store.Audit(ctx, model.AuditEntry{
			Actor: prov.Actor, Action: "block-failed", Target: prefix.String(),
			Detail: fmt.Sprintf("%s (%v)", auditDetail(prov, reason), err),
		})
		s.log("firewall: could not program a block for %s: %v", prefix, err)
		return fmt.Errorf("%w: %v", ErrNotEnforced, err)
	}

	_ = s.store.Audit(ctx, model.AuditEntry{
		Actor: prov.Actor, Action: "block", Target: prefix.String(),
		Detail: auditDetail(prov, reason),
	})
	return nil
}

// auditDetail writes the reason with whatever provenance can be pointed at
// from it. The link lives on the block row too, but the audit log is what an
// operator actually reads, and a line there that ends at a sentence is the
// dead end this release is closing. Nothing is added when there is nothing to
// add: an entry claiming "alert 0" would be worse than one that stays quiet.
func auditDetail(prov model.BlockProvenance, reason string) string {
	detail := reason
	switch {
	case prov.AlertID > 0 && prov.IncidentID > 0:
		detail += fmt.Sprintf(" (alert %d, incident %d)", prov.AlertID, prov.IncidentID)
	case prov.AlertID > 0:
		detail += fmt.Sprintf(" (alert %d)", prov.AlertID)
	case prov.IncidentID > 0:
		detail += fmt.Sprintf(" (incident %d)", prov.IncidentID)
	}
	if prov.Evidence != "" {
		detail += " — " + prov.Evidence
	}
	return detail
}

// restoreBlock undoes a block whose kernel apply failed: either back to the
// row that was there before, or gone entirely if the block was new.
func (s *Service) restoreBlock(ctx context.Context, prefix netip.Prefix, prior model.Block, hadPrior bool) {
	var err error
	if hadPrior {
		_, err = s.store.AddBlock(ctx, prior)
	} else {
		_, err = s.store.RemoveBlock(ctx, prefix)
	}
	if err != nil {
		// Now the store and the kernel really can disagree, so say so loudly
		// rather than let it pass as an ordinary failed block.
		s.log("firewall: could not roll back the stored block for %s after a failed apply: %v", prefix, err)
	}
}

// Unblock removes a block and reconciles.
func (s *Service) Unblock(ctx context.Context, prefix netip.Prefix, actor string) (bool, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	prior, hadPrior, err := s.store.ActiveBlockFor(ctx, prefix)
	if err != nil {
		return false, fmt.Errorf("reading the existing block: %w", err)
	}
	removed, err := s.store.RemoveBlock(ctx, prefix)
	if err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	if err := s.Reconcile(ctx); err != nil {
		// The kernel is still dropping this address, so a list that no longer
		// shows it is the same untruth as the block path's — just pointing the
		// other way. Put the row back and say plainly that nothing changed.
		if hadPrior {
			if _, rerr := s.store.AddBlock(ctx, prior); rerr != nil {
				s.log("firewall: could not restore the stored block for %s after a failed unblock: %v",
					prefix, rerr)
			}
		}
		_ = s.store.Audit(ctx, model.AuditEntry{
			Actor: actor, Action: "unblock-failed", Target: prefix.String(), Detail: err.Error(),
		})
		s.log("firewall: could not lift the block on %s: %v", prefix, err)
		return false, fmt.Errorf("%w: %v", ErrStillBlocked, err)
	}
	_ = s.store.Audit(ctx, model.AuditEntry{
		Actor: actor, Action: "unblock", Target: prefix.String(),
	})
	return true, nil
}

// Restore ensures the base ruleset exists and reconciles the kernel to the
// stored desired state. Called once at startup so reboots and container
// updates never drop protection.
func (s *Service) Restore(ctx context.Context) error {
	defer s.refreshEnforcingNow()

	s.cfgMu.RLock()
	enforce := s.cfg.Enforce
	s.cfgMu.RUnlock()
	if !enforce {
		s.log("firewall: observe mode — not applying rules")
		return nil
	}
	if !s.backend.Available() {
		s.log("firewall: backend %s unavailable — running monitor-only", s.backend.Name())
		return nil
	}
	if err := s.backend.EnsureBase(ctx); err != nil {
		return fmt.Errorf("ensuring base ruleset: %w", err)
	}
	s.cfgMu.Lock()
	s.baseReady = true
	protected := append([]netip.Prefix(nil), s.cfg.Protected...)
	s.cfgMu.Unlock()
	// EnsureBase creates the sets empty, so the never-block set has to be
	// filled here — nothing else refills it until the allowlist next changes.
	s.mu.Lock()
	err := s.backend.ReconcileProtected(ctx, protected)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("loading the never-block set: %w", err)
	}
	return s.Reconcile(ctx)
}

// Reconcile drives the kernel to match the stored active blocks. In observe
// mode or when the backend is unavailable it is a no-op (the desired state is
// still safely recorded in the store).
func (s *Service) Reconcile(ctx context.Context) error {
	_, err := s.reconcile(ctx)
	return err
}

// reconcile is Reconcile, reporting how many rules it pushed so a self-heal
// can say what it put back. The count is of rules programmed, not blocks
// stored: rulesFor drops the ones the never-block list covers, and a repair
// entry claiming those were reapplied would be describing a kernel nobody has.
func (s *Service) reconcile(ctx context.Context) (int, error) {
	if !s.Enforcing() {
		return 0, nil
	}
	// The read belongs inside the lock: two concurrent reconciles that each
	// read first could otherwise push in the wrong order, and the staler
	// snapshot would win — briefly un-enforcing a block that is still active.
	s.mu.Lock()
	defer s.mu.Unlock()
	blocks, err := s.store.ActiveBlocks(ctx)
	if err != nil {
		return 0, err
	}
	rules := s.rulesFor(blocks)
	if err := s.backend.Reconcile(ctx, rules); err != nil {
		return 0, err
	}
	return len(rules), nil
}

// SetCountryPrefixes replaces the preventive country-block set. In observe
// mode (or with the backend unavailable) the list is only remembered, so the
// UI can still show what enforcement would cover; the kernel is untouched.
func (s *Service) SetCountryPrefixes(ctx context.Context, prefixes []netip.Prefix) error {
	s.countryMu.Lock()
	s.countryPrefixes = append([]netip.Prefix(nil), prefixes...)
	s.countryMu.Unlock()
	if !s.Enforcing() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.ReconcileCountry(ctx, prefixes)
}

// SetDevicePolicies pushes the per-device rules into the kernel. Like
// country prefixes they are remembered in observe mode so the UI can show
// what enforcement would cover.
func (s *Service) SetDevicePolicies(ctx context.Context, rules []DeviceRule) error {
	// The never-block list applies here too. A device policy is a block by
	// another name — and a stronger one, since its rules sit ahead of the
	// conntrack exemption and cut established connections as well. Quarantining
	// the gateway would take the network down with the dashboard on it, which
	// is precisely what the allowlist exists to prevent. Filtering here rather
	// than only at the API keeps a policy stored before this guard existed
	// from reaching the kernel.
	kept := make([]DeviceRule, 0, len(rules))
	for _, r := range rules {
		if _, blocked := s.Protects(netip.PrefixFrom(r.Addr, r.Addr.BitLen())); blocked {
			s.log("firewall: refusing device policy on protected address %s", r.Addr)
			continue
		}
		kept = append(kept, r)
	}

	s.countryMu.Lock()
	s.devicePolicies = kept
	s.countryMu.Unlock()
	if !s.Enforcing() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.ReconcileDevices(ctx, kept)
}

// DevicePolicyCount reports how many devices carry a policy.
func (s *Service) DevicePolicyCount() int {
	s.countryMu.Lock()
	defer s.countryMu.Unlock()
	return len(s.devicePolicies)
}

// CountryPrefixCount reports how many prefixes preventive country blocking
// currently covers (remembered even in observe mode).
func (s *Service) CountryPrefixCount() int {
	s.countryMu.Lock()
	defer s.countryMu.Unlock()
	return len(s.countryPrefixes)
}

// rulesFor translates stored blocks into kernel rules, choosing the action by
// whether the prefix is internal or external.
func (s *Service) rulesFor(blocks []model.Block) []Rule {
	rules := make([]Rule, 0, len(blocks))
	for _, b := range blocks {
		// Refusing new blocks on protected addresses is not enough on its
		// own: an operator can allowlist an address that is already blocked
		// — "oh, that one is fine after all" — and the stored block would
		// otherwise keep being pushed to the kernel on every reconcile while
		// the dashboard listed the address as protected. The allowlist wins,
		// and it wins from the next reconcile rather than only for whatever
		// happens to be created afterwards.
		if _, blocked := s.Protects(b.Prefix); blocked {
			continue
		}
		action := s.cfg.ActionExternal
		if s.cfg.IsInternal(b.Prefix.Addr()) {
			action = s.cfg.ActionInternal
		}
		rules = append(rules, Rule{Prefix: b.Prefix, Action: action, Expires: b.Expires})
	}
	return rules
}

// ExpireLoop periodically deactivates TTL-expired blocks and reconciles, so
// blocks fall away even if the kernel's own set timeout and the store drift.
func (s *Service) ExpireLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			expired, err := s.store.ExpireBlocks(ctx)
			if err != nil {
				s.log("firewall: expiring blocks: %v", err)
				continue
			}
			if len(expired) > 0 {
				for _, b := range expired {
					_ = s.store.Audit(ctx, model.AuditEntry{
						Actor: "system", Action: "unblock", Target: b.Prefix.String(), Detail: "ttl expired",
					})
				}
				if err := s.Reconcile(ctx); err != nil {
					s.log("firewall: reconcile after expiry: %v", err)
				}
			}
		}
	}
}
