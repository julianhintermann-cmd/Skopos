package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

// Temporary verification of the inspector decoding. Deleted before hand-off:
// test files are outside this task's file boundary.

func bounds(t *testing.T, spans []span, expires *time.Time) []elemBound {
	t.Helper()
	var out []elemBound
	for _, s := range spans {
		out = append(out,
			elemBound{bound: startBound(setKey(s.lo)), expires: expires},
			elemBound{bound: endBound(setKey(s.hi)), end: true},
		)
	}
	return out
}

func TestScratchDecodePrefix(t *testing.T) {
	spans := unionPrefixes([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	views, trunc := decodeRanges(bounds(t, spans, nil), true)
	if trunc || len(views) != 1 {
		t.Fatalf("views = %+v truncated=%v", views, trunc)
	}
	if views[0].Prefix != "203.0.113.0/24" || views[0].From != "203.0.113.0" || views[0].To != "203.0.113.255" {
		t.Fatalf("view = %+v", views[0])
	}
}

func TestScratchDecodeTopOfFamily(t *testing.T) {
	for _, p := range []string{"255.255.255.0/24", "240.0.0.0/4", "ffff::/16"} {
		spans := unionPrefixes([]netip.Prefix{netip.MustParsePrefix(p)})
		views, _ := decodeRanges(bounds(t, spans, nil), true)
		if len(views) != 1 {
			t.Fatalf("%s: views = %+v", p, views)
		}
		if views[0].Prefix != p {
			t.Errorf("%s: prefix = %q", p, views[0].Prefix)
		}
		want := "255.255.255.255"
		if netip.MustParsePrefix(p).Addr().Is6() {
			want = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
		}
		if views[0].To != want {
			t.Errorf("%s: to = %q, want %q", p, views[0].To, want)
		}
	}
}

func TestScratchDecodeNonPrefixRange(t *testing.T) {
	// Two blocks with different expiries: decompose keeps them apart, and the
	// second segment is not a CIDR block.
	soon := time.Now().Add(time.Hour)
	spans := decompose([]Rule{
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Expires: &soon},
		{Prefix: netip.MustParsePrefix("10.0.0.0/25")},
	})
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2", len(spans))
	}
	var els []elemBound
	for _, s := range spans {
		els = append(els,
			elemBound{bound: startBound(setKey(s.lo)), expires: s.expires},
			elemBound{bound: endBound(setKey(s.hi)), end: true},
		)
	}
	views, _ := decodeRanges(els, true)
	if len(views) != 2 {
		t.Fatalf("views = %+v", views)
	}
	if views[0].Prefix != "10.0.0.0/25" || views[0].Expires != nil {
		t.Errorf("first = %+v", views[0])
	}
	if views[1].Prefix != "10.0.0.128/25" || views[1].From != "10.0.0.128" || views[1].To != "10.0.0.255" {
		t.Errorf("second = %+v", views[1])
	}
	if views[1].Expires == nil {
		t.Errorf("second range lost its expiry: %+v", views[1])
	}
}

func TestScratchDecodeTrulyNonPrefix(t *testing.T) {
	lo, _ := intervalBounds(netip.MustParsePrefix("10.0.0.0/24"))
	_, hi := intervalBounds(netip.MustParsePrefix("10.0.1.0/25"))
	views, _ := decodeRanges([]elemBound{
		{bound: startBound(setKey(lo))},
		{bound: endBound(setKey(hi)), end: true},
	}, true)
	if len(views) != 1 {
		t.Fatalf("views = %+v", views)
	}
	if views[0].Prefix != "" {
		t.Errorf("fabricated a CIDR for a range that is not one: %+v", views[0])
	}
	if views[0].From != "10.0.0.0" || views[0].To != "10.0.1.127" {
		t.Errorf("view = %+v", views[0])
	}
}

func TestScratchDecodeSingleAddresses(t *testing.T) {
	a := netip.MustParseAddr("192.168.1.44")
	views, _ := decodeRanges([]elemBound{{bound: startBound(ipBytes(a))}}, false)
	if len(views) != 1 || views[0].From != views[0].To || views[0].Prefix != "192.168.1.44/32" {
		t.Fatalf("views = %+v", views)
	}
}

func TestScratchTruncation(t *testing.T) {
	var els []elemBound
	for i := 0; i < maxRanges+50; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 32)
		lo, hi := intervalBounds(p)
		els = append(els,
			elemBound{bound: startBound(setKey(lo))},
			elemBound{bound: endBound(setKey(hi)), end: true},
		)
	}
	views, trunc := decodeRanges(els, true)
	if !trunc || len(views) != maxRanges {
		t.Fatalf("views = %d truncated = %v", len(views), trunc)
	}
}

func TestScratchMemoryDumpAndIntent(t *testing.T) {
	ctx := context.Background()
	b := NewMemoryBackend(true)
	if err := b.Reconcile(ctx, []Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.5/32"), Action: Drop},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Action: Reject},
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := b.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Sets) != 14 || len(snap.Chains) != 3 {
		t.Fatalf("sets = %d chains = %d", len(snap.Sets), len(snap.Chains))
	}
	for _, ch := range snap.Chains {
		if ch.Rules != nil || ch.Err == "" {
			t.Errorf("chain %s claims rules it does not have: %+v", ch.Name, ch)
		}
	}
	byName := map[string]SetSnapshot{}
	for _, s := range snap.Sets {
		if s.Elements == nil {
			t.Fatalf("set %s reports an unknown count from a backend that knows", s.Name)
		}
		byName[s.Name] = s
	}
	if n := *byName[setDrop4].Elements; n != 1 {
		t.Errorf("drop4 elements = %d", n)
	}
	if got := byName[setReject6].Ranges[0].Prefix; got != "2001:db8::/32" {
		t.Errorf("reject6 range = %q", got)
	}
	if n := *byName[setCountry4].Elements; n != 0 {
		t.Errorf("country4 elements = %d, want a real zero", n)
	}

	// The JSON must spell unknown as null and empty as 0.
	raw, err := json.Marshal(SetSnapshot{Name: "drop4", Err: "boom"})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"name":"drop4","present":false,"elements":null,"truncated":false,"error":"boom"}` {
		t.Fatalf("unreadable set encodes as %s", raw)
	}
}
