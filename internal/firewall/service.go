package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
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
	for _, p := range s.cfg.Protected {
		if p.Overlaps(prefix) {
			return p, true
		}
	}
	return netip.Prefix{}, false
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

// Block records a block (origin: detector) and reconciles. It implements
// policy.Blocker. ttl <= 0 falls back to the configured default.
func (s *Service) Block(ctx context.Context, prefix netip.Prefix, reason string, ttl time.Duration) error {
	return s.block(ctx, prefix, model.OriginDetector, "detector", reason, ttl)
}

// ManualBlock records an operator-initiated block (permanent unless ttl > 0).
// It refuses anything covering the allowlist or the gateway: the detector
// path has always been held to that, and a block placed by hand reaches the
// kernel through exactly the same rules.
func (s *Service) ManualBlock(ctx context.Context, prefix netip.Prefix, actor, reason string, ttl time.Duration) error {
	if p, ok := s.Protects(prefix); ok {
		return fmt.Errorf("%w: %s covers %s", ErrProtected, prefix, p)
	}
	return s.block(ctx, prefix, model.OriginManual, actor, reason, ttl)
}

func (s *Service) block(ctx context.Context, prefix netip.Prefix, origin model.BlockOrigin, actor, reason string, ttl time.Duration) error {
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
	b := model.Block{Prefix: prefix, Origin: origin, Reason: reason, Expires: expires}
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
			Actor: actor, Action: "block-failed", Target: prefix.String(),
			Detail: fmt.Sprintf("%s (%v)", reason, err),
		})
		s.log("firewall: could not program a block for %s: %v", prefix, err)
		return fmt.Errorf("%w: %v", ErrNotEnforced, err)
	}

	_ = s.store.Audit(ctx, model.AuditEntry{
		Actor: actor, Action: "block", Target: prefix.String(), Detail: reason,
	})
	return nil
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
	removed, err := s.store.RemoveBlock(ctx, prefix)
	if err != nil {
		return false, err
	}
	if removed {
		_ = s.store.Audit(ctx, model.AuditEntry{
			Actor: actor, Action: "unblock", Target: prefix.String(),
		})
		if err := s.Reconcile(ctx); err != nil {
			return true, err
		}
	}
	return removed, nil
}

// Restore ensures the base ruleset exists and reconciles the kernel to the
// stored desired state. Called once at startup so reboots and container
// updates never drop protection.
func (s *Service) Restore(ctx context.Context) error {
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
	if !s.Enforcing() {
		return nil
	}
	// The read belongs inside the lock: two concurrent reconciles that each
	// read first could otherwise push in the wrong order, and the staler
	// snapshot would win — briefly un-enforcing a block that is still active.
	s.mu.Lock()
	defer s.mu.Unlock()
	blocks, err := s.store.ActiveBlocks(ctx)
	if err != nil {
		return err
	}
	return s.backend.Reconcile(ctx, s.rulesFor(blocks))
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
