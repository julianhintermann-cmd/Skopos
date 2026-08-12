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

	b := NewNFTablesBackend()
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

func TestIntegrationEnsureBaseIdempotent(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend()
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("first EnsureBase: %v", err)
	}
	// Calling again must not error (it rebuilds cleanly).
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("second EnsureBase: %v", err)
	}
}
