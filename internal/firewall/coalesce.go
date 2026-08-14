package firewall

import (
	"bytes"
	"net/netip"
	"slices"
	"sort"
	"time"
)

// span is a half-open address range [lo, hi) in the big-endian byte form that
// nftables interval sets store, together with the expiry that applies across
// the whole range. A nil expires means the range never expires.
type span struct {
	lo, hi  []byte
	expires *time.Time
}

// coalesceRules turns the desired block rules into non-overlapping ranges, one
// list per kernel set.
//
// The kernel's rbtree sets reject overlapping intervals outright: adding a /32
// next to the /24 that already contains it fails the entire netlink batch with
// EEXIST. Because a batch is atomic and Reconcile refills from the store every
// time, that one rejection then wedges every later reconcile — no block, no
// unblock and no expiry reaches the kernel again — while the dashboard goes on
// listing all of them as active. Overlap is not exotic: a detector auto-blocks
// an address and the operator later blocks its network from the alert.
//
// A plain merge is not sufficient, because the ranges carry expiries. A
// permanent /24 absorbing a one-hour /32 really is one permanent range. A
// one-hour /24 containing a permanent /32 is not — collapsing it to the longer
// expiry would hold 255 uninvolved addresses blocked forever, and collapsing it
// to the shorter one would release an address the operator blocked for good.
// So the ranges are cut into elementary segments and each segment takes the
// latest expiry among the rules covering it; touching segments are rejoined
// only when their expiries agree.
func coalesceRules(rules []Rule) map[string][]span {
	bySet := map[string][]Rule{}
	for _, r := range rules {
		// A /0 would blackhole the whole address family, and it cannot get
		// here from the API any more — but a row written by an older build
		// still can, and one such row used to wedge every later reconcile.
		if !r.Prefix.IsValid() || r.Prefix.Bits() == 0 {
			continue
		}
		name, ok := setFor(r)
		if !ok {
			continue
		}
		bySet[name] = append(bySet[name], r)
	}
	out := make(map[string][]span, len(bySet))
	for name, rs := range bySet {
		if spans := decompose(rs); len(spans) > 0 {
			out[name] = spans
		}
	}
	return out
}

// decompose cuts a set's rules into non-overlapping segments carrying the
// correct per-segment expiry. Cost is O(n²) in the rule count, which is the
// right trade for the block sets: n is the number of active blocks, so tens,
// and the clarity is worth more than the asymptote. The large sets (country,
// LAN, protected) carry no expiry and go through unionPrefixes instead.
func decompose(rules []Rule) []span {
	type bound struct {
		lo, hi  []byte
		expires *time.Time
	}
	items := make([]bound, 0, len(rules))
	cuts := make([][]byte, 0, 2*len(rules))
	for _, r := range rules {
		lo, hi := intervalBounds(r.Prefix)
		items = append(items, bound{lo: lo, hi: hi, expires: r.Expires})
		cuts = append(cuts, lo, hi)
	}
	if len(items) == 0 {
		return nil
	}

	sort.Slice(cuts, func(i, j int) bool { return bytes.Compare(cuts[i], cuts[j]) < 0 })
	cuts = slices.CompactFunc(cuts, func(a, b []byte) bool { return bytes.Equal(a, b) })

	var out []span
	for i := 0; i+1 < len(cuts); i++ {
		lo, hi := cuts[i], cuts[i+1]
		var (
			covered bool
			expires *time.Time
			forever bool
		)
		for _, it := range items {
			// The segment lies inside this rule when the rule starts no later
			// and ends no earlier. Segments are elementary, so partial overlap
			// cannot occur.
			if bytes.Compare(it.lo, lo) > 0 || bytes.Compare(it.hi, hi) < 0 {
				continue
			}
			covered = true
			if it.expires == nil {
				// A permanent rule outlives every dated one covering the same
				// addresses, so the segment is permanent and stays that way.
				forever = true
				expires = nil
				continue
			}
			if !forever && (expires == nil || it.expires.After(*expires)) {
				t := *it.expires
				expires = &t
			}
		}
		if !covered {
			continue
		}
		// Rejoin with the previous segment only when they touch and agree on
		// when they end — merging across different expiries is what would
		// silently over- or under-block.
		if n := len(out); n > 0 && bytes.Equal(out[n-1].hi, lo) && sameExpiry(out[n-1].expires, expires) {
			out[n-1].hi = hi
			continue
		}
		out = append(out, span{lo: lo, hi: hi, expires: expires})
	}
	return out
}

// sameExpiry reports whether two expiries describe the same deadline, treating
// nil (never) as its own value.
func sameExpiry(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

// unionPrefixes merges a prefix list into the smallest set of non-overlapping
// ranges. It serves the sets that carry no expiry — country, LAN and the
// never-block list — where a plain union is all that is needed and the input
// can be very large: a single country's prefix list runs to tens of thousands
// of entries, so this stays O(n log n) rather than going through decompose.
//
// The never-block set is the one that made this urgent. protectedFromConfig
// appends the resolved default gateway as a /32 on top of whatever the operator
// allowlisted, so an allowlist of the LAN — which is exactly what the example
// config suggests — produced an overlapping pair on a completely clean install.
// Restore then aborted before it programmed a single block.
func unionPrefixes(prefixes []netip.Prefix) []span {
	spans := make([]span, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		lo, hi := intervalBounds(p)
		spans = append(spans, span{lo: lo, hi: hi})
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if c := bytes.Compare(spans[i].lo, spans[j].lo); c != 0 {
			return c < 0
		}
		// Widest first, so a containing range absorbs what follows it.
		return bytes.Compare(spans[i].hi, spans[j].hi) > 0
	})

	out := make([]span, 0, len(spans))
	out = append(out, spans[0])
	for _, s := range spans[1:] {
		last := &out[len(out)-1]
		// Touching counts as joinable here: with no expiry to preserve, two
		// adjacent ranges are indistinguishable from one wider range.
		if len(s.lo) == len(last.hi) && bytes.Compare(s.lo, last.hi) <= 0 {
			if bytes.Compare(s.hi, last.hi) > 0 {
				last.hi = s.hi
			}
			continue
		}
		out = append(out, s)
	}
	return out
}
