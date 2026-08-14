package firewall

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// render prints a span list in a form that makes an expiry mistake obvious at
// a glance, because that is the failure mode these tests exist to catch: a
// merge that silently extends or shortens how long addresses stay blocked.
func render(spans []span, base time.Time) string {
	parts := make([]string, 0, len(spans))
	for _, s := range spans {
		lo, _ := netip.AddrFromSlice(setKey(s.lo))
		hi, _ := netip.AddrFromSlice(setKey(s.hi))
		when := "permanent"
		if s.expires != nil {
			when = fmt.Sprintf("+%s", s.expires.Sub(base))
		}
		parts = append(parts, fmt.Sprintf("[%s..%s) %s", lo, hi, when))
	}
	return strings.Join(parts, " | ")
}

func TestCoalesceRules(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := base.Add(d); return &t }
	hour, day := at(time.Hour), at(24*time.Hour)

	cases := []struct {
		name  string
		rules []Rule
		want  string
	}{{
		// The kernel rejected this pair outright before coalescing existed.
		// It is the operator's exact sequence: block an address, then block
		// the network around it from the alert.
		name: "permanent network absorbs a dated address inside it",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop},
			{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop, Expires: hour},
		},
		want: "[203.0.113.0..203.0.114.0) permanent",
	}, {
		// The case that makes a naive "longest expiry wins" merge wrong: the
		// whole /24 must not inherit the /32's permanence, or 255 uninvolved
		// addresses stay blocked forever.
		name: "dated network keeps its own expiry around a permanent address",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop, Expires: hour},
			{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop},
		},
		want: "[203.0.113.0..203.0.113.7) +1h0m0s | " +
			"[203.0.113.7..203.0.113.8) permanent | " +
			"[203.0.113.8..203.0.114.0) +1h0m0s",
	}, {
		name: "the longer of two expiries wins only over the addresses it covers",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop, Expires: hour},
			{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop, Expires: day},
		},
		want: "[203.0.113.0..203.0.113.7) +1h0m0s | " +
			"[203.0.113.7..203.0.113.8) +24h0m0s | " +
			"[203.0.113.8..203.0.114.0) +1h0m0s",
	}, {
		name: "adjacent ranges with different expiries stay apart",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/25"), Action: Drop, Expires: hour},
			{Prefix: netip.MustParsePrefix("203.0.113.128/25"), Action: Drop},
		},
		want: "[203.0.113.0..203.0.113.128) +1h0m0s | [203.0.113.128..203.0.114.0) permanent",
	}, {
		name: "adjacent ranges that agree on expiry become one",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/25"), Action: Drop},
			{Prefix: netip.MustParsePrefix("203.0.113.128/25"), Action: Drop},
		},
		want: "[203.0.113.0..203.0.114.0) permanent",
	}, {
		name: "an exact duplicate collapses",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop},
			{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop},
		},
		want: "[203.0.113.7..203.0.113.8) permanent",
	}, {
		// A hole between two blocks is meaningful: merging across it would
		// block addresses nobody asked to block.
		name: "disjoint networks keep the gap between them",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop},
			{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Action: Drop},
		},
		want: "[198.51.100.0..198.51.101.0) permanent | [203.0.113.0..203.0.114.0) permanent",
	}, {
		name: "IPv6 nests the same way",
		rules: []Rule{
			{Prefix: netip.MustParsePrefix("2001:db8::/64"), Action: Drop},
			{Prefix: netip.MustParsePrefix("2001:db8::1/128"), Action: Drop, Expires: hour},
		},
		want: "[2001:db8::..2001:db8:0:1::) permanent",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := coalesceRules(tc.rules)
			if len(out) != 1 {
				t.Fatalf("expected one set, got %d: %v", len(out), out)
			}
			for _, spans := range out {
				if got := render(spans, base); got != tc.want {
					t.Errorf("\n got: %s\nwant: %s", got, tc.want)
				}
			}
		})
	}
}

// Drop and Reject land in different kernel sets, so an address blocked one way
// and a network blocked the other must not be merged into each other.
func TestCoalesceKeepsActionsApart(t *testing.T) {
	out := coalesceRules([]Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop},
		{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Reject},
	})
	if len(out) != 2 {
		t.Fatalf("expected drop and reject sets, got %d: %v", len(out), out)
	}
	if len(out[setDrop4]) != 1 || len(out[setReject4]) != 1 {
		t.Fatalf("each set should hold one range: %v", out)
	}
}

func TestCoalesceSeparatesFamilies(t *testing.T) {
	out := coalesceRules([]Rule{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: Drop},
		{Prefix: netip.MustParsePrefix("2001:db8::/64"), Action: Drop},
	})
	if len(out[setDrop4]) != 1 || len(out[setDrop6]) != 1 {
		t.Fatalf("v4 and v6 belong in different sets: %v", out)
	}
}

// The never-block list is built from the operator's allowlist plus the
// resolved default gateway, so an allowlist of the LAN produces an overlapping
// pair on a clean install. That used to abort startup before a single block
// was programmed.
func TestUnionPrefixesMergesTheAllowlistAndGateway(t *testing.T) {
	got := unionPrefixes([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.1.1/32"),
	})
	if want := "[192.168.1.0..192.168.2.0) permanent"; render(got, time.Time{}) != want {
		t.Errorf("\n got: %s\nwant: %s", render(got, time.Time{}), want)
	}
}

func TestUnionPrefixesKeepsDisjointRanges(t *testing.T) {
	got := unionPrefixes([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
	})
	want := "[10.0.0.0..11.0.0.0) permanent | " +
		"[172.16.0.0..172.32.0.0) permanent | " +
		"[192.168.0.0..192.169.0.0) permanent"
	if render(got, time.Time{}) != want {
		t.Errorf("\n got: %s\nwant: %s", render(got, time.Time{}), want)
	}
}

// An expired rule must not resurrect the addresses around it: the segment it
// contributed simply disappears once its deadline passes.
func TestCoalesceHandlesEmptyAndInvalid(t *testing.T) {
	if out := coalesceRules(nil); len(out) != 0 {
		t.Errorf("no rules should yield no sets, got %v", out)
	}
	if out := coalesceRules([]Rule{{Action: Drop}}); len(out) != 0 {
		t.Errorf("an invalid prefix should be skipped, got %v", out)
	}
	if out := unionPrefixes(nil); out != nil {
		t.Errorf("no prefixes should yield no spans, got %v", out)
	}
}

// A range that reaches the last address of the family has an exclusive end one
// past the maximum, which does not fit in an address. Dropping such prefixes
// would silently lose ordinary entries from a threat feed or a hand-kept list,
// so they have to survive coalescing and reach the kernel as a wrap to zero.
func TestCoalesceKeepsRangesThatReachTheTopOfTheFamily(t *testing.T) {
	cases := []struct{ prefix, want string }{
		{"255.255.255.0/24", "[255.255.255.0..0.0.0.0) permanent"},
		{"240.0.0.0/4", "[240.0.0.0..0.0.0.0) permanent"},
		{"255.255.255.255/32", "[255.255.255.255..0.0.0.0) permanent"},
		{"ffff::/16", "[ffff::..::) permanent"},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			out := coalesceRules([]Rule{{Prefix: netip.MustParsePrefix(tc.prefix), Action: Drop}})
			if len(out) != 1 {
				t.Fatalf("%s was dropped instead of coalesced: %v", tc.prefix, out)
			}
			for _, spans := range out {
				if got := render(spans, time.Time{}); got != tc.want {
					t.Errorf("\n got: %s\nwant: %s", got, tc.want)
				}
			}
		})
	}
}

// A /0 is refused as policy, not because it cannot be rendered: it would
// blackhole the family, dashboard included.
func TestCoalesceRefusesWholeFamily(t *testing.T) {
	out := coalesceRules([]Rule{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Action: Drop},
		{Prefix: netip.MustParsePrefix("::/0"), Action: Drop},
		{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Action: Drop},
	})
	if len(out) != 1 || len(out[setDrop4]) != 1 {
		t.Fatalf("only the ordinary block should survive: %v", out)
	}
	if got := render(out[setDrop4], time.Time{}); got != "[203.0.113.7..203.0.113.8) permanent" {
		t.Errorf("got %s", got)
	}
}
