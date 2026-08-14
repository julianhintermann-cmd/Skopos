//go:build linux && integration

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestIntegrationDumpReadsTheKernelBack(t *testing.T) {
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
	// A country range that runs to the top of the family: the kernel stores its
	// end as an all-zero key, which read literally is 0.0.0.0.
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
	if len(snap.Chains) != 3 || len(snap.Sets) != len(allSets) {
		t.Fatalf("chains = %d sets = %d", len(snap.Chains), len(snap.Sets))
	}
	for _, ch := range snap.Chains {
		if !ch.Present || ch.Rules == nil || ch.Expected == nil {
			t.Fatalf("chain %s = %+v", ch.Name, ch)
		}
		if *ch.Rules != *ch.Expected {
			t.Errorf("chain %s holds %d rules, EnsureBase recorded %d", ch.Name, *ch.Rules, *ch.Expected)
		}
	}

	sets := map[string]SetSnapshot{}
	for _, s := range snap.Sets {
		if !s.Present || s.Elements == nil || s.Err != "" {
			t.Fatalf("set %s = %+v", s.Name, s)
		}
		sets[s.Name] = s
	}
	// Two ranges, two elements each: this is the kernel's own count, not the
	// number of ranges, and the field says so.
	if n := *sets[setDrop4].Elements; n != 4 {
		t.Errorf("drop4 elements = %d, want 4", n)
	}
	byFrom := map[string]RangeView{}
	for _, v := range sets[setDrop4].Ranges {
		byFrom[v.From] = v
	}
	if v := byFrom["203.0.113.5"]; v.Prefix != "203.0.113.5/32" || v.To != "203.0.113.5" {
		t.Errorf("blocked address = %+v", v)
	} else if v.Expires == nil || v.Expires.After(hour.Add(time.Minute)) || v.Expires.Before(time.Now()) {
		t.Errorf("kernel timeout came back as %v, want about %v", v.Expires, hour)
	}
	if v := byFrom["198.51.100.0"]; v.Prefix != "198.51.100.0/24" || v.To != "198.51.100.255" {
		t.Errorf("blocked network = %+v", v)
	} else if v.Expires != nil {
		t.Errorf("a permanent block came back with an expiry: %v", v.Expires)
	}
	if v := sets[setReject6].Ranges; len(v) != 1 || v[0].Prefix != "2001:db8::/32" {
		t.Errorf("reject6 = %+v", v)
	}
	if v := sets[setCountry4].Ranges; len(v) != 1 || v[0].Prefix != "240.0.0.0/4" || v[0].To != "255.255.255.255" {
		t.Errorf("top-of-family range = %+v", v)
	}
	if v := sets[setDevQuar4].Ranges; len(v) != 1 || v[0].From != "192.168.1.44" || v[0].From != v[0].To {
		t.Errorf("device address = %+v", v)
	}
	if v := sets[setLAN4].Ranges; len(v) != 1 || v[0].Prefix != "192.168.0.0/16" {
		t.Errorf("lan range = %+v", v)
	}
	if n := *sets[setReject4].Elements; n != 0 {
		t.Errorf("reject4 = %d; an empty set must report a measured zero", n)
	}

	// Read-only: the verification that passed before the dump still passes.
	if err := b.Verify(ctx); err != nil {
		t.Fatalf("Verify after Dump: %v", err)
	}
}

// A wiped kernel is a finding, not a failed read: the dump succeeds, the table
// is false, and no set reports a count. Rendering that as fourteen empty sets
// would be indistinguishable from a healthy install with nothing blocked.
func TestIntegrationDumpOverAnEmptyKernel(t *testing.T) {
	enterNetNS(t)

	snap, err := NewNFTablesBackend(nil).Dump(context.Background())
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if snap.Table {
		t.Error("reported a table that is not there")
	}
	for _, s := range snap.Sets {
		if s.Present || s.Elements != nil {
			t.Errorf("set %s = %+v", s.Name, s)
		}
	}
	for _, ch := range snap.Chains {
		if ch.Present || ch.Rules != nil || ch.Expected != nil {
			t.Errorf("chain %s = %+v", ch.Name, ch)
		}
	}
}

// One dump is seventeen netlink reads and a blocked country is tens of
// thousands of elements, so a caller refreshing faster than dumpMinInterval is
// served the last read again — dated with the age it really has.
func TestIntegrationDumpReusesARecentRead(t *testing.T) {
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
	second, err := b.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReadAt.Equal(first.ReadAt) || !second.Table {
		t.Errorf("re-read the kernel within %v: %v then %v", dumpMinInterval, first.ReadAt, second.ReadAt)
	}
}
