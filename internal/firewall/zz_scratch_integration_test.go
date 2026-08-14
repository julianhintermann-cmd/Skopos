//go:build linux && integration

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
)

// Temporary verification of Dump against a real kernel. Deleted before
// hand-off: test files are outside this task's file boundary.

func TestIntegrationScratchDumpReadsTheKernel(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()

	b := NewNFTablesBackend([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	hour := time.Now().Add(time.Hour)
	if err := b.Reconcile(ctx, []Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.5/32"), Action: Drop, Expires: &hour},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: Drop},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Action: Reject},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// A country range that runs to the top of the family: its end key is all
	// zeroes in the kernel and must not render as 0.0.0.0.
	if err := b.ReconcileCountry(ctx, []netip.Prefix{netip.MustParsePrefix("240.0.0.0/4")}); err != nil {
		t.Fatalf("ReconcileCountry: %v", err)
	}
	if err := b.ReconcileDevices(ctx, []DeviceRule{
		{Addr: netip.MustParseAddr("192.168.1.44"), Policy: DeviceQuarantine},
	}); err != nil {
		t.Fatalf("ReconcileDevices: %v", err)
	}

	snap, err := b.Dump(ctx)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if !snap.Table || snap.ReadAt.IsZero() {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(snap.Chains) != 3 || len(snap.Sets) != 14 {
		t.Fatalf("chains = %d sets = %d", len(snap.Chains), len(snap.Sets))
	}
	for _, ch := range snap.Chains {
		if !ch.Present || ch.Rules == nil || ch.Expected == nil {
			t.Fatalf("chain %s = %+v", ch.Name, ch)
		}
		if *ch.Rules != *ch.Expected {
			t.Errorf("chain %s holds %d rules, recorded %d", ch.Name, *ch.Rules, *ch.Expected)
		}
		t.Logf("chain %s: rules %d, expected %d", ch.Name, *ch.Rules, *ch.Expected)
	}

	sets := map[string]SetSnapshot{}
	for _, s := range snap.Sets {
		if !s.Present || s.Elements == nil || s.Err != "" {
			t.Fatalf("set %s = %+v", s.Name, s)
		}
		sets[s.Name] = s
	}
	if n := *sets[setDrop4].Elements; n != 4 {
		t.Errorf("drop4 elements = %d, want 4 (two ranges, two elements each)", n)
	}
	got := map[string]RangeView{}
	for _, v := range sets[setDrop4].Ranges {
		got[v.From] = v
	}
	if v := got["203.0.113.5"]; v.Prefix != "203.0.113.5/32" || v.To != "203.0.113.5" {
		t.Errorf("single blocked address = %+v", v)
	} else if v.Expires == nil || v.Expires.After(hour.Add(time.Minute)) || v.Expires.Before(time.Now()) {
		t.Errorf("kernel timeout not reported sanely: %+v", v.Expires)
	}
	if v := got["198.51.100.0"]; v.Prefix != "198.51.100.0/24" || v.To != "198.51.100.255" {
		t.Errorf("blocked network = %+v", v)
	} else if v.Expires != nil {
		t.Errorf("permanent block came back with an expiry: %v", v.Expires)
	}
	if v := sets[setReject6].Ranges; len(v) != 1 || v[0].Prefix != "2001:db8::/32" {
		t.Errorf("reject6 ranges = %+v", v)
	}
	if v := sets[setCountry4].Ranges; len(v) != 1 || v[0].To != "255.255.255.255" || v[0].Prefix != "240.0.0.0/4" {
		t.Errorf("top-of-family range = %+v", v)
	}
	if v := sets[setDevQuar4].Ranges; len(v) != 1 || v[0].From != "192.168.1.44" || v[0].From != v[0].To {
		t.Errorf("device range = %+v", v)
	}
	if v := sets[setLAN4].Ranges; len(v) != 1 || v[0].Prefix != "192.168.0.0/16" {
		t.Errorf("lan range = %+v", v)
	}
	if n := *sets[setReject4].Elements; n != 0 {
		t.Errorf("reject4 = %d, want a real zero", n)
	}

	// Dump must not have changed anything: the verification that ran before it
	// must still pass after.
	if err := b.Verify(ctx); err != nil {
		t.Fatalf("Verify after Dump: %v", err)
	}

	// A fresh backend over a wiped kernel: the table is gone, and that is the
	// finding, not an error. No set may report a count.
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := c.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		c.DelTable(tb)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	empty, err := NewNFTablesBackend(nil).Dump(ctx)
	if err != nil {
		t.Fatalf("Dump over an empty kernel: %v", err)
	}
	if empty.Table {
		t.Error("reported a table that is gone")
	}
	for _, s := range empty.Sets {
		if s.Present || s.Elements != nil {
			t.Errorf("set %s = %+v over an empty kernel", s.Name, s)
		}
	}
	for _, ch := range empty.Chains {
		if ch.Present || ch.Rules != nil || ch.Expected != nil {
			t.Errorf("chain %s = %+v over an empty kernel", ch.Name, ch)
		}
	}
}

func TestIntegrationScratchDumpReusesRecentReads(t *testing.T) {
	enterNetNS(t)
	ctx := context.Background()
	b := NewNFTablesBackend(nil)
	if err := b.EnsureBase(ctx); err != nil {
		t.Fatalf("EnsureBase: %v", err)
	}
	first, err := b.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReadAt.Equal(first.ReadAt) {
		t.Errorf("re-read the whole kernel within %v", dumpMinInterval)
	}
}
