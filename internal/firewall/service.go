package firewall

import (
	"context"
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
}

// Service ties the store, backend and config together. It implements
// policy.Blocker and owns reconciliation, restore-on-start and TTL expiry.
type Service struct {
	cfg     Config
	backend Backend
	store   Store
	clock   func() time.Time
	log     func(string, ...any)

	mu sync.Mutex

	countryMu       sync.Mutex
	countryPrefixes []netip.Prefix
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

// Enforcing reports whether the service is in enforce mode and the backend can
// actually apply rules.
func (s *Service) Enforcing() bool {
	return s.cfg.Enforce && s.backend.Available()
}

// Block records a block (origin: detector) and reconciles. It implements
// policy.Blocker. ttl <= 0 falls back to the configured default.
func (s *Service) Block(ctx context.Context, prefix netip.Prefix, reason string, ttl time.Duration) error {
	return s.block(ctx, prefix, model.OriginDetector, "detector", reason, ttl)
}

// ManualBlock records an operator-initiated block (permanent unless ttl > 0).
func (s *Service) ManualBlock(ctx context.Context, prefix netip.Prefix, actor, reason string, ttl time.Duration) error {
	return s.block(ctx, prefix, model.OriginManual, actor, reason, ttl)
}

func (s *Service) block(ctx context.Context, prefix netip.Prefix, origin model.BlockOrigin, actor, reason string, ttl time.Duration) error {
	if ttl <= 0 && origin == model.OriginDetector {
		ttl = s.cfg.DefaultTTL
	}
	var expires *time.Time
	if ttl > 0 {
		t := s.clock().Add(ttl)
		expires = &t
	}
	b := model.Block{Prefix: prefix, Origin: origin, Reason: reason, Expires: expires}
	if _, err := s.store.AddBlock(ctx, b); err != nil {
		return fmt.Errorf("recording block: %w", err)
	}
	_ = s.store.Audit(ctx, model.AuditEntry{
		Actor: actor, Action: "block", Target: prefix.String(), Detail: reason,
	})
	return s.Reconcile(ctx)
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
	if !s.cfg.Enforce {
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
	return s.Reconcile(ctx)
}

// Reconcile drives the kernel to match the stored active blocks. In observe
// mode or when the backend is unavailable it is a no-op (the desired state is
// still safely recorded in the store).
func (s *Service) Reconcile(ctx context.Context) error {
	if !s.Enforcing() {
		return nil
	}
	blocks, err := s.store.ActiveBlocks(ctx)
	if err != nil {
		return err
	}
	rules := s.rulesFor(blocks)

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Reconcile(ctx, rules)
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
