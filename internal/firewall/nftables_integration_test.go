//go:build linux && integration

// These tests exercise the real nftables backend inside a throwaway network
// namespace. They need root (CAP_NET_ADMIN) and are gated behind the
// "integration" build tag, so `go test ./...` skips them and CI runs them
// explicitly with: go test -tags=integration -run Integration ./internal/firewall/...
package firewall

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

func enterNetNS(t *testing.T) {
	t.Helper()
	if unix.Geteuid() != 0 {
		t.Skip("nftables integration tests require root")
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("cannot create network namespace: %v", err)
	}
}

func TestIntegrationEnsureBaseAndReconcile(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend(nil)
	if !b.Available() {
		t.Fatal("backend should be available as root with nftables")
	}
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}

	// Block one IPv4 /32 (drop) and one IPv6 (reject) with a TTL.
	future := time.Now().Add(time.Hour)
	rules := []Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.5/32"), Action: Drop, Expires: &future},
		{Prefix: netip.MustParsePrefix("2001:db8::1/128"), Action: Reject},
	}
	if err := b.Reconcile(ctx, rules); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Read the sets back through a fresh connection.
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	var table *nftables.Table
	for _, tb := range tables {
		if tb.Name == tableName {
			table = tb
		}
	}
	if table == nil {
		t.Fatal("skopos table not found after EnsureBase")
	}

	drop4, err := c.GetSetByName(table, setDrop4)
	if err != nil {
		t.Fatalf("GetSetByName drop4: %v", err)
	}
	elems, err := c.GetSetElements(drop4)
	if err != nil {
		t.Fatalf("GetSetElements: %v", err)
	}
	if len(elems) == 0 {
		t.Error("expected the blocked IPv4 to be present in drop4 set")
	}

	// Reconcile to empty must clear the set.
	if err := b.Reconcile(ctx, nil); err != nil {
		t.Fatalf("Reconcile empty: %v", err)
	}
	elems, _ = c.GetSetElements(drop4)
	if len(elems) != 0 {
		t.Errorf("drop4 set should be empty after reconciling to no rules, got %d", len(elems))
	}
}

func TestIntegrationReconcileCountry(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend(nil)
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}

	// Enough prefixes to cross the chunking boundary, mixed families.
	var prefixes []netip.Prefix
	for i := 0; i < 1200; i++ {
		prefixes = append(prefixes, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{5, byte(i / 256), byte(i % 256), 0}), 24))
	}
	prefixes = append(prefixes, netip.MustParsePrefix("2a00::/16"))

	if err := b.ReconcileCountry(ctx, prefixes); err != nil {
		t.Fatalf("ReconcileCountry: %v", err)
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	var table *nftables.Table
	for _, tb := range tables {
		if tb.Name == tableName {
			table = tb
		}
	}
	if table == nil {
		t.Fatal("skopos table not found")
	}
	c4, err := c.GetSetByName(table, setCountry4)
	if err != nil {
		t.Fatalf("GetSetByName country4: %v", err)
	}
	elems, err := c.GetSetElements(c4)
	if err != nil {
		t.Fatalf("GetSetElements: %v", err)
	}
	// Interval sets round-trip as start/end pairs; exact accounting differs
	// by kernel, so assert order of magnitude, not equality.
	if len(elems) < 1200 {
		t.Errorf("country4 has %d elements, want >= 1200", len(elems))
	}

	// Replacing with a shorter list shrinks the set.
	if err := b.ReconcileCountry(ctx, prefixes[:10]); err != nil {
		t.Fatalf("ReconcileCountry shrink: %v", err)
	}
	elems, _ = c.GetSetElements(c4)
	if len(elems) == 0 || len(elems) > 40 {
		t.Errorf("country4 after shrink has %d elements, want a handful", len(elems))
	}

	// And clearing empties it.
	if err := b.ReconcileCountry(ctx, nil); err != nil {
		t.Fatalf("ReconcileCountry clear: %v", err)
	}
	elems, _ = c.GetSetElements(c4)
	if len(elems) != 0 {
		t.Errorf("country4 after clear has %d elements, want 0", len(elems))
	}
}

func TestIntegrationEnsureBaseIdempotent(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend(nil)
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("first EnsureBase: %v", err)
	}
	// Calling again must not error (it rebuilds cleanly).
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("second EnsureBase: %v", err)
	}
}

func TestIntegrationReconcileDevices(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend([]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	if err := b.ReconcileDevices(ctx, []DeviceRule{
		{Addr: netip.MustParseAddr("192.168.1.50"), Policy: DeviceLANOnly},
		{Addr: netip.MustParseAddr("192.168.1.51"), Policy: DeviceQuarantine},
	}); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, _ := c.ListTables()
	var table *nftables.Table
	for _, tb := range tables {
		if tb.Name == tableName {
			table = tb
		}
	}
	if table == nil {
		t.Fatal("skopos table not found")
	}
	for name, want := range map[string]int{setDevLANOnly4: 1, setDevQuar4: 1} {
		set, err := c.GetSetByName(table, name)
		if err != nil {
			t.Fatalf("GetSetByName %s: %v", name, err)
		}
		els, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("GetSetElements %s: %v", name, err)
		}
		if len(els) != want {
			t.Errorf("%s has %d elements, want %d", name, len(els), want)
		}
	}
	// The LAN set the lan_only rule compares against must be populated too.
	lan, err := c.GetSetByName(table, setLAN4)
	if err != nil {
		t.Fatalf("GetSetByName lan4: %v", err)
	}
	if els, _ := c.GetSetElements(lan); len(els) == 0 {
		t.Error("lan4 must hold the configured private ranges")
	}

	// Clearing empties the device sets.
	if err := b.ReconcileDevices(ctx, nil); err != nil {
		t.Fatal(err)
	}
	set, _ := c.GetSetByName(table, setDevQuar4)
	if els, _ := c.GetSetElements(set); len(els) != 0 {
		t.Errorf("device set should be empty after clearing, got %d", len(els))
	}
}

// Blocking one address must not disturb any other set. Reconcile used to
// range over every set in the table, flushing each and refilling only the
// four it owns — so a single auto-block silently emptied the country sets,
// the LAN ranges the per-device rules compare against, the never-block set,
// and the device sets themselves. The dashboard went on reporting the counts
// it had last loaded. This is the regression test for that.
func TestIntegrationReconcileLeavesOtherSetsAlone(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	lan := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	b := NewNFTablesBackend(lan)
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}

	if err := b.ReconcileCountry(ctx, []netip.Prefix{
		netip.MustParsePrefix("5.0.0.0/8"),
		netip.MustParsePrefix("2a00::/16"),
	}); err != nil {
		t.Fatalf("ReconcileCountry: %v", err)
	}
	if err := b.ReconcileProtected(ctx, []netip.Prefix{
		netip.MustParsePrefix("192.168.1.1/32"),
	}); err != nil {
		t.Fatalf("ReconcileProtected: %v", err)
	}
	if err := b.ReconcileDevices(ctx, []DeviceRule{
		{Addr: netip.MustParseAddr("192.168.1.50"), Policy: DeviceQuarantine},
		{Addr: netip.MustParseAddr("192.168.1.51"), Policy: DeviceLANOnly},
	}); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}

	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	var table *nftables.Table
	tables, err := c.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		if tb.Name == tableName {
			table = tb
		}
	}
	if table == nil {
		t.Fatal("skopos table not found")
	}
	count := func(name string) int {
		t.Helper()
		set, err := c.GetSetByName(table, name)
		if err != nil {
			t.Fatalf("GetSetByName %s: %v", name, err)
		}
		elems, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("GetSetElements %s: %v", name, err)
		}
		return len(elems)
	}

	watched := []string{setCountry4, setCountry6, setProtected4, setLAN4, setDevQuar4, setDevLANOnly4}
	before := map[string]int{}
	for _, name := range watched {
		before[name] = count(name)
		if before[name] == 0 {
			t.Fatalf("%s should be populated before the block", name)
		}
	}

	// One ordinary block — the thing that happens every time a detector fires.
	if err := b.Reconcile(ctx, []Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	for _, name := range watched {
		if got := count(name); got != before[name] {
			t.Errorf("%s went from %d to %d elements after an unrelated block", name, before[name], got)
		}
	}
	if got := count(setDrop4); got == 0 {
		t.Error("drop4 should hold the block that was just applied")
	}

	// And the reverse: refreshing the country list must not disturb the block.
	if err := b.ReconcileCountry(ctx, []netip.Prefix{netip.MustParsePrefix("6.0.0.0/8")}); err != nil {
		t.Fatalf("ReconcileCountry refresh: %v", err)
	}
	if got := count(setDrop4); got == 0 {
		t.Error("the block disappeared when the country list was refreshed")
	}
}
