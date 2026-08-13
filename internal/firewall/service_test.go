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
	svc.SetProtected([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	})
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
