package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

// The decoding these tests cover is the inverse of what spanElements writes, so
// the two have to be checked against each other rather than against a fixture:
// a decoder that agrees with itself would render every range the wrong way
// round just as confidently.

func elemsFor(spans []span) []elemBound {
	var out []elemBound
	for _, s := range spans {
		out = append(out,
			elemBound{bound: startBound(setKey(s.lo)), expires: s.expires},
			elemBound{bound: endBound(setKey(s.hi)), end: true},
		)
	}
	return out
}

func TestDumpDecodesAPrefix(t *testing.T) {
	spans := unionPrefixes([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	views, truncated := decodeRanges(elemsFor(spans), true)
	if truncated || len(views) != 1 {
		t.Fatalf("views = %+v truncated = %v", views, truncated)
	}
	if views[0].Prefix != "203.0.113.0/24" || views[0].From != "203.0.113.0" || views[0].To != "203.0.113.255" {
		t.Fatalf("view = %+v", views[0])
	}
}

// A range that reaches the top of the family is stored with an all-zero end
// key. Read literally that is 0.0.0.0, which would put the range at the
// opposite end of the internet from where it is.
func TestDumpDecodesTheTopOfTheFamily(t *testing.T) {
	for _, p := range []string{"255.255.255.0/24", "240.0.0.0/4", "ffff::/16"} {
		spans := unionPrefixes([]netip.Prefix{netip.MustParsePrefix(p)})
		views, _ := decodeRanges(elemsFor(spans), true)
		if len(views) != 1 {
			t.Fatalf("%s: views = %+v", p, views)
		}
		want := "255.255.255.255"
		if netip.MustParsePrefix(p).Addr().Is6() {
			want = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
		}
		if views[0].To != want || views[0].Prefix != p {
			t.Errorf("%s decoded as %+v", p, views[0])
		}
	}
}

// Two blocks over the same addresses with different expiries stay two ranges
// (see decompose), and the second one is not a CIDR block. Each keeps its own
// expiry, which is the property that stops a coalesced view from silently
// extending or cutting one of them short.
func TestDumpDecodesAdjacentRangesWithTheirOwnExpiries(t *testing.T) {
	hour := time.Now().Add(time.Hour)
	spans := decompose([]Rule{
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), Expires: &hour},
		{Prefix: netip.MustParsePrefix("10.0.0.0/25")},
	})
	views, _ := decodeRanges(elemsFor(spans), true)
	if len(views) != 2 {
		t.Fatalf("views = %+v", views)
	}
	if views[0].Prefix != "10.0.0.0/25" || views[0].Expires != nil {
		t.Errorf("permanent half = %+v", views[0])
	}
	if views[1].Prefix != "10.0.0.128/25" || views[1].Expires == nil {
		t.Errorf("expiring half = %+v", views[1])
	}
}

// The coalescer legitimately produces ranges that are not prefixes. Rendering
// one as the nearest CIDR block would be a fabrication in the one view whose
// whole job is to be believed.
func TestDumpNeverInventsACIDRForARangeThatIsNotOne(t *testing.T) {
	lo, _ := intervalBounds(netip.MustParsePrefix("10.0.0.0/24"))
	_, hi := intervalBounds(netip.MustParsePrefix("10.0.1.0/25"))
	views, _ := decodeRanges([]elemBound{
		{bound: startBound(setKey(lo))},
		{bound: endBound(setKey(hi)), end: true},
	}, true)
	if len(views) != 1 {
		t.Fatalf("views = %+v", views)
	}
	if views[0].Prefix != "" || views[0].From != "10.0.0.0" || views[0].To != "10.0.1.127" {
		t.Fatalf("view = %+v", views[0])
	}
}

// The dev_* sets hold single addresses and are not interval sets, so there is
// nothing to pair.
func TestDumpDecodesSingleAddresses(t *testing.T) {
	a := netip.MustParseAddr("192.168.1.44")
	views, _ := decodeRanges([]elemBound{{bound: startBound(ipBytes(a))}}, false)
	if len(views) != 1 || views[0].From != views[0].To || views[0].Prefix != "192.168.1.44/32" {
		t.Fatalf("views = %+v", views)
	}
}

func TestDumpTruncatesLongSetsAndSaysSo(t *testing.T) {
	var els []elemBound
	for i := range maxRanges + 50 {
		lo, hi := intervalBounds(netip.PrefixFrom(
			netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 32))
		els = append(els,
			elemBound{bound: startBound(setKey(lo))},
			elemBound{bound: endBound(setKey(hi)), end: true},
		)
	}
	views, truncated := decodeRanges(els, true)
	if !truncated || len(views) != maxRanges {
		t.Fatalf("views = %d truncated = %v", len(views), truncated)
	}
}

// nil is unknown and 0 is empty, all the way out to the wire. A set that could
// not be read must not encode as a set holding nothing: that is what the 0.2.1
// defect looked like from the outside, and telling the two apart is the reason
// this endpoint exists.
func TestSetSnapshotEncodesUnknownAsNull(t *testing.T) {
	unread, err := json.Marshal(SetSnapshot{Name: "drop4", Err: "reading set drop4: no such file or directory"})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"name":"drop4","present":false,"elements":null,"truncated":false,` +
		`"error":"reading set drop4: no such file or directory"}`
	if string(unread) != want {
		t.Fatalf("unreadable set encoded as %s", unread)
	}
	zero := 0
	empty, err := json.Marshal(SetSnapshot{Name: "drop4", Present: true, Elements: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != `{"name":"drop4","present":true,"elements":0,"truncated":false}` {
		t.Fatalf("empty set encoded as %s", empty)
	}
}

func TestMemoryBackendDumpReportsWhatItHolds(t *testing.T) {
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
	if len(snap.Sets) != len(allSets) || len(snap.Chains) != 3 {
		t.Fatalf("sets = %d chains = %d", len(snap.Sets), len(snap.Chains))
	}
	// The memory backend has no chains, and a fake that answered like a healthy
	// kernel would let these tests pass over the hole the inspector exists to
	// find.
	for _, ch := range snap.Chains {
		if ch.Rules != nil || ch.Err == "" {
			t.Errorf("chain %s = %+v", ch.Name, ch)
		}
	}
	sets := map[string]SetSnapshot{}
	for _, s := range snap.Sets {
		if s.Elements == nil {
			t.Fatalf("set %s reports no count from a backend that knows exactly", s.Name)
		}
		sets[s.Name] = s
	}
	if n := *sets[setDrop4].Elements; n != 1 {
		t.Errorf("drop4 = %d", n)
	}
	if got := sets[setReject6].Ranges; len(got) != 1 || got[0].Prefix != "2001:db8::/32" {
		t.Errorf("reject6 ranges = %+v", got)
	}
	if n := *sets[setCountry4].Elements; n != 0 {
		t.Errorf("country4 = %d, and that zero has to be a measured one", n)
	}
}
