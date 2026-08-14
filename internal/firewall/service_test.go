package firewall

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(store.Options{
		Path:  filepath.Join(t.TempDir(), "skopos.db"),
		Clock: func() time.Time { return time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func newTestService(t *testing.T, cfg Config, backend Backend) (*Service, *store.Store) {
	t.Helper()
	st := openStore(t)
	svc := NewService(cfg, backend, st, func() time.Time { return time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC) })
	// Mirror the real startup sequence. Enforcing() now requires the base
	// ruleset to actually exist, so a service that never restored is one that
	// is not enforcing — which is the honest answer, and the reason the tests
	// have to come up the same way the app does.
	if err := svc.Restore(context.Background()); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	return svc, st
}

func baseConfig(enforce bool) Config {
	return Config{
		Enforce:        enforce,
		ActionExternal: Drop,
		ActionInternal: Reject,
		DefaultTTL:     24 * time.Hour,
		IsInternal: func(a netip.Addr) bool {
			return netip.MustParsePrefix("192.168.0.0/16").Contains(a)
		},
	}
}

func TestBlockRecordsAndReconciles(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	if err := svc.Block(ctx, netip.MustParsePrefix("203.0.113.5/32"), "feeds hit", 0); err != nil {
		t.Fatal(err)
	}

	// Recorded in the store.
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Fatalf("active blocks = %d, want 1", len(active))
	}
	// Applied to the kernel with the external action (drop).
	current := backend.Current()
	if len(current) != 1 || current[0].Action != Drop {
		t.Fatalf("reconciled rules = %+v", current)
	}
	// Detector block got the default TTL.
	if active[0].Expires == nil {
		t.Error("detector block should have a TTL from the default")
	}
}

func TestInternalBlockUsesRejectAction(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, _ := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	if err := svc.ManualBlock(ctx, netip.MustParsePrefix("192.168.1.50/32"), "admin", "misbehaving", 0); err != nil {
		t.Fatal(err)
	}
	current := backend.Current()
	if len(current) != 1 || current[0].Action != Reject {
		t.Fatalf("internal block should use reject, got %+v", current)
	}
}

func TestObserveModeRecordsButDoesNotReconcile(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, st := newTestService(t, baseConfig(false), backend) // observe
	ctx := context.Background()

	if err := svc.Block(ctx, netip.MustParsePrefix("203.0.113.5/32"), "feeds", 0); err != nil {
		t.Fatal(err)
	}
	// Desired state is safely recorded...
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Errorf("observe mode should still record the block, got %d", len(active))
	}
	// ...but the kernel is never touched.
	if backend.ReconcileCalls() != 0 {
		t.Errorf("observe mode must not reconcile, got %d calls", backend.ReconcileCalls())
	}
}

func TestDegradedBackendDoesNotReconcile(t *testing.T) {
	backend := NewMemoryBackend(false) // capability missing
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	if err := svc.Block(ctx, netip.MustParsePrefix("203.0.113.5/32"), "feeds", 0); err != nil {
		t.Fatal(err)
	}
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Errorf("block should still be recorded when backend is degraded, got %d", len(active))
	}
	if backend.ReconcileCalls() != 0 {
		t.Errorf("unavailable backend must not reconcile, got %d", backend.ReconcileCalls())
	}
	if svc.Enforcing() {
		t.Error("Enforcing() must be false when the backend is unavailable")
	}
}

func TestRestoreReappliesStoredBlocks(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	// Simulate blocks already in the store (e.g. from before a restart).
	_, _ = st.AddBlock(ctx, model.Block{Prefix: netip.MustParsePrefix("203.0.113.5/32"), Origin: model.OriginManual})
	_, _ = st.AddBlock(ctx, model.Block{Prefix: netip.MustParsePrefix("203.0.113.6/32"), Origin: model.OriginDetector})

	if err := svc.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if backend.baseEnsured == 0 {
		t.Error("Restore should ensure the base ruleset")
	}
	if len(backend.Current()) != 2 {
		t.Errorf("Restore should reapply all stored blocks, got %d", len(backend.Current()))
	}
}

func TestUnblockRemovesAndReconciles(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, _ := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()
	p := netip.MustParsePrefix("203.0.113.5/32")

	_ = svc.Block(ctx, p, "feeds", 0)
	removed, err := svc.Unblock(ctx, p, "admin")
	if err != nil || !removed {
		t.Fatalf("Unblock = %v, %v", removed, err)
	}
	if len(backend.Current()) != 0 {
		t.Errorf("kernel should have no rules after unblock, got %d", len(backend.Current()))
	}
}

func TestSetCountryPrefixesEnforced(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, _ := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	prefixes := []netip.Prefix{
		netip.MustParsePrefix("5.0.0.0/8"),
		netip.MustParsePrefix("2a00::/16"),
	}
	if err := svc.SetCountryPrefixes(ctx, prefixes); err != nil {
		t.Fatal(err)
	}
	if got := backend.CurrentCountry(); len(got) != 2 {
		t.Fatalf("kernel country prefixes = %d, want 2", len(got))
	}
	if svc.CountryPrefixCount() != 2 {
		t.Errorf("CountryPrefixCount = %d, want 2", svc.CountryPrefixCount())
	}

	// Clearing propagates too.
	if err := svc.SetCountryPrefixes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := backend.CurrentCountry(); len(got) != 0 {
		t.Errorf("kernel country prefixes after clear = %d, want 0", len(got))
	}
}

func TestSetCountryPrefixesObserveOnlyRemembers(t *testing.T) {
	backend := NewMemoryBackend(true)
	svc, _ := newTestService(t, baseConfig(false), backend)
	ctx := context.Background()

	if err := svc.SetCountryPrefixes(ctx, []netip.Prefix{netip.MustParsePrefix("5.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	if backend.CountryCalls() != 0 {
		t.Error("observe mode must not touch the kernel")
	}
	// Remembered anyway, so the UI can show coverage before arming.
	if svc.CountryPrefixCount() != 1 {
		t.Errorf("CountryPrefixCount = %d, want 1", svc.CountryPrefixCount())
	}
}

// A block placed by hand reaches the kernel through the same rules as one
// placed by a detector. The detector path has always refused the gateway;
// the operator's own button is one tap on a phone, and the address it would
// take down is the one they need to reach the dashboard from.
func TestManualBlockRefusesProtected(t *testing.T) {
	svc, _ := newTestService(t, baseConfig(true), NewMemoryBackend(true))
	if err := svc.SetProtected(context.Background(), []netip.Prefix{
		netip.MustParsePrefix("192.168.1.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	cases := []struct {
		name    string
		prefix  string
		refused bool
	}{
		{"the gateway itself", "192.168.1.1/32", true},
		{"a range containing the gateway", "192.168.1.0/24", true},
		{"an allowlisted range", "10.0.0.0/8", true},
		{"inside an allowlisted range", "10.1.2.3/32", true},
		{"a neighbour of the gateway", "192.168.1.2/32", false},
		{"an outside address", "203.0.113.7/32", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.ManualBlock(ctx, netip.MustParsePrefix(tc.prefix), "operator", "test", 0)
			if tc.refused && !errors.Is(err, ErrProtected) {
				t.Errorf("blocking %s returned %v, want ErrProtected", tc.prefix, err)
			}
			if !tc.refused && err != nil {
				t.Errorf("blocking %s failed: %v", tc.prefix, err)
			}
		})
	}
}

// An empty never-block set blocks nothing extra — the guard must not become a
// silent no-op firewall.
func TestManualBlockAllowedWithoutProtectedSet(t *testing.T) {
	svc, _ := newTestService(t, baseConfig(true), NewMemoryBackend(true))
	if err := svc.ManualBlock(context.Background(), netip.MustParsePrefix("203.0.113.7/32"), "operator", "", 0); err != nil {
		t.Fatalf("ManualBlock: %v", err)
	}
}

// failingBackend applies nothing and reports why, so the store-versus-kernel
// rollback can be exercised without a kernel.
type failingBackend struct {
	*MemoryBackend
	fail bool
}

func (f *failingBackend) Reconcile(ctx context.Context, desired []Rule) error {
	if f.fail {
		return errors.New("kernel said no")
	}
	return f.MemoryBackend.Reconcile(ctx, desired)
}

// A block whose kernel apply fails must leave nothing behind claiming the
// address is blocked. The operator saw an error and a new entry at the same
// time and could not tell which one was true.
func TestBlockRollsBackWhenTheKernelRefuses(t *testing.T) {
	backend := &failingBackend{MemoryBackend: NewMemoryBackend(true)}
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()

	backend.fail = true
	err := svc.ManualBlock(ctx, netip.MustParsePrefix("203.0.113.7/32"), "admin", "test", 0)
	if !errors.Is(err, ErrNotEnforced) {
		t.Fatalf("want ErrNotEnforced, got %v", err)
	}
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 0 {
		t.Errorf("a failed block left %d rows behind: %+v", len(active), active)
	}
}

// And the mirror: an unblock the kernel refuses must not remove the row, or
// the list stops showing an address the kernel is still dropping.
func TestUnblockRollsBackWhenTheKernelRefuses(t *testing.T) {
	backend := &failingBackend{MemoryBackend: NewMemoryBackend(true)}
	svc, st := newTestService(t, baseConfig(true), backend)
	ctx := context.Background()
	prefix := netip.MustParsePrefix("203.0.113.7/32")

	if err := svc.ManualBlock(ctx, prefix, "admin", "test", 0); err != nil {
		t.Fatalf("the initial block should succeed: %v", err)
	}

	backend.fail = true
	removed, err := svc.Unblock(ctx, prefix, "admin")
	if !errors.Is(err, ErrStillBlocked) {
		t.Fatalf("want ErrStillBlocked, got %v", err)
	}
	if removed {
		t.Error("a refused unblock must not report the block as removed")
	}
	active, _ := st.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Errorf("the block should still be listed, got %d rows", len(active))
	}
}

// stateService builds a service whose clock the test drives, so staleness can
// be reached without waiting six minutes for it.
func stateService(t *testing.T, enforce bool) (*Service, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	svc := NewService(baseConfig(enforce), NewMemoryBackend(true), openStore(t), func() time.Time { return now })
	if err := svc.Restore(context.Background()); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	return svc, &now
}

// Observe mode reports observing, not enforcing — even though Verify records
// OK for it. That true means "there was nothing to check"; rendering it as
// enforcement is the exact defect this whole mechanism exists to prevent, and
// it would be an easy one to reintroduce by reading health.OK directly.
func TestStateObserveModeIsNotEnforcing(t *testing.T) {
	svc, _ := stateService(t, false)
	svc.recordHealth(true, true, nil)

	if got := svc.State().Verdict; got != VerdictObserving {
		t.Errorf("verdict = %q, want %q", got, VerdictObserving)
	}
	if svc.EnforcingNow() {
		t.Error("observe mode must not report enforcing to the packet path")
	}
}

// Before the first verification there is no evidence, and the honest answer is
// that nobody has looked — not that everything is fine. This covers the first
// two minutes of every process life.
func TestStateBeforeAnyCheckIsUnverified(t *testing.T) {
	svc, _ := stateService(t, true)

	st := svc.State()
	if st.Verdict != VerdictUnverified {
		t.Errorf("verdict = %q, want %q", st.Verdict, VerdictUnverified)
	}
	if !st.CheckedAt.IsZero() {
		t.Errorf("checked_at = %v, want zero for never-checked", st.CheckedAt)
	}
	if svc.EnforcingNow() {
		t.Error("an unverified firewall must not report enforcing")
	}
}

func TestStateFreshPassIsEnforcing(t *testing.T) {
	svc, _ := stateService(t, true)
	svc.recordHealth(true, true, nil)

	if got := svc.State().Verdict; got != VerdictEnforcing {
		t.Errorf("verdict = %q, want %q", got, VerdictEnforcing)
	}
	if !svc.EnforcingNow() {
		t.Error("a fresh confirmed pass should reach the packet path")
	}
}

// The hole this closes: before StaleAfter existed, a passing check stayed
// green for the life of the process. If the verify goroutine died — panicked,
// never started, lost its context — every screen went on reporting protection
// from a reading that could be days old. An old pass is not a pass.
func TestStatePassGoesStaleAndDemotes(t *testing.T) {
	svc, now := stateService(t, true)
	svc.recordHealth(true, true, nil)
	if got := svc.State().Verdict; got != VerdictEnforcing {
		t.Fatalf("precondition: verdict = %q, want %q", got, VerdictEnforcing)
	}

	// One second inside the window still counts.
	*now = now.Add(StaleAfter - time.Second)
	if got := svc.State().Verdict; got != VerdictEnforcing {
		t.Errorf("just inside the window: verdict = %q, want %q", got, VerdictEnforcing)
	}

	// One second past it does not.
	*now = now.Add(2 * time.Second)
	if got := svc.State().Verdict; got != VerdictUnverified {
		t.Errorf("past StaleAfter: verdict = %q, want %q — a reading that never "+
			"expires is how a dead check stays green", got, VerdictUnverified)
	}
}

func TestStateFailedCheckIsDegraded(t *testing.T) {
	svc, _ := stateService(t, true)
	svc.recordHealth(false, true, errors.New("the blocks4 set is empty in the kernel"))

	st := svc.State()
	if st.Verdict != VerdictDegraded {
		t.Errorf("verdict = %q, want %q", st.Verdict, VerdictDegraded)
	}
	if st.Error == "" {
		t.Error("a degraded state must carry what went wrong")
	}
	if st.FailingSince.IsZero() {
		t.Error("a degraded state must say since when")
	}
	if svc.EnforcingNow() {
		t.Error("a degraded firewall must not report enforcing")
	}
}

// A check that could not read the desired state covered less ground than
// usual. Reporting that as a clean bill of health is how a narrower check
// becomes invisible.
func TestStateCheckThatSkippedTheSetsIsPartial(t *testing.T) {
	svc, _ := stateService(t, true)
	svc.recordHealth(true, false, nil)

	if got := svc.State().Verdict; got != VerdictPartial {
		t.Errorf("verdict = %q, want %q", got, VerdictPartial)
	}
	if svc.EnforcingNow() {
		t.Error("partial is not confirmed, so the packet path must not treat it as such")
	}
}

// StaleAfter is derived from the verify cadence rather than written twice.
// Two constants that must agree are two constants that will eventually differ.
func TestStaleAfterTracksTheVerifyInterval(t *testing.T) {
	if StaleAfter != 3*VerifyInterval {
		t.Errorf("StaleAfter = %v, want 3 × VerifyInterval (%v)", StaleAfter, 3*VerifyInterval)
	}
}
