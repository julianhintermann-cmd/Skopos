// Package firewall applies and reconciles IP blocks. The store holds the
// desired state (active blocks); a Backend drives the kernel toward it. In v1
// the only real backend is nftables; a memory backend backs the tests and a
// monitor-only backend keeps Skopos running when the kernel cannot enforce.
package firewall

import (
	"bytes"
	"context"
	"net/netip"
	"sort"
	"time"
)

// Action is what happens to a blocked packet.
type Action string

const (
	// Drop discards silently — the peer learns nothing.
	Drop Action = "drop"
	// Reject answers with an error — friendlier for accidental LAN blocks.
	Reject Action = "reject"
)

// Rule is one desired block in the kernel: a prefix, the action to take, and
// an optional expiry that maps to an nftables set timeout.
type Rule struct {
	Prefix  netip.Prefix
	Action  Action
	Expires *time.Time
}

// DevicePolicy is what a per-device rule enforces.
type DevicePolicy string

const (
	// DeviceLANOnly drops the device's traffic to and from the internet
	// while leaving local traffic alone — the IoT lockdown.
	DeviceLANOnly DevicePolicy = "lan_only"
	// DeviceQuarantine drops all of the device's traffic, local included.
	DeviceQuarantine DevicePolicy = "quarantine"
)

// DeviceRule confines one device by address.
type DeviceRule struct {
	Addr   netip.Addr
	Policy DevicePolicy
}

// Backend is the kernel abstraction. Implementations must be idempotent:
// EnsureBase can be called on every start, and Reconcile makes the kernel's
// block set exactly match desired, adding and removing as needed.
type Backend interface {
	// EnsureBase creates the table, chains and sets if absent.
	EnsureBase(ctx context.Context) error
	// Reconcile makes the enforced rule set exactly equal to desired.
	Reconcile(ctx context.Context, desired []Rule) error
	// ReconcileDevices replaces the per-device policy rules: which LAN
	// devices may reach the internet, and which are cut off entirely.
	ReconcileDevices(ctx context.Context, rules []DeviceRule) error
	// ReconcileCountry replaces the preventive country-block prefix sets.
	// Separate from Reconcile because the volume differs by orders of
	// magnitude (one country is tens of thousands of prefixes), the data
	// changes rarely, and the semantics differ: country prefixes drop
	// unsolicited inbound traffic only, never replies to connections the
	// LAN itself opened.
	ReconcileCountry(ctx context.Context, prefixes []netip.Prefix) error
	// ReconcileProtected replaces the never-block set. Its rule accepts a
	// matching source ahead of the country drop, so an address the operator
	// marked never-block keeps reaching them even when its whole country is
	// blocked. It sits behind the per-device policies deliberately: those are
	// explicit, per-device decisions and are refused for protected addresses
	// before they ever get here.
	ReconcileProtected(ctx context.Context, prefixes []netip.Prefix) error
	// Available reports whether the backend can actually enforce (required
	// capabilities and kernel support present).
	Available() bool
	// Verify reads the kernel back and reports whether the structures Skopos
	// programmed are still there. Available() only proves the interface can be
	// opened, which says nothing about whether someone ran `nft flush ruleset`
	// an hour ago — and a firewall that reports enforcing over an empty kernel
	// is the most dangerous thing this product can do.
	Verify(ctx context.Context) error
	// SetCounts reports how many elements each set currently holds. Existence
	// is not enough: the 0.2.1 defect left every set in place and emptied the
	// ones it should not have touched, so a check that only asks "is the set
	// there" would not have caught the bug this verification exists for.
	SetCounts(ctx context.Context) (map[string]int, error)
	// Dump reads back everything Skopos programmed: the table, the three
	// chains with their rule counts, and every set with its element count and
	// the ranges those elements decode to. It is the one method here that
	// writes nothing.
	//
	// SetCounts already asks the kernel these questions, but it answers only
	// this package, so until now the only answer available to anyone asking
	// "is this address really blocked" came from the database's intention.
	// Implementations must report what they could not read as unknown, never
	// as zero — see Snapshot.
	Dump(ctx context.Context) (Snapshot, error)
	// Name identifies the backend for logs and the system view.
	Name() string
}

// Snapshot is what a backend found in the kernel at ReadAt.
//
// The pointers in it are the whole point. A set that could not be read and a
// set that is genuinely empty are different facts, and the second one is the
// symptom the 0.2.1 defect produced: every set present, four of them emptied,
// and nothing anywhere that could tell the two apart. Anything unknown is nil.
type Snapshot struct {
	ReadAt time.Time `json:"read_at"`
	// Table is whether the skopos table is in the kernel at all. False is not
	// a failure to report — it is the finding, and the alarming one.
	Table  bool            `json:"table"`
	Chains []ChainSnapshot `json:"chains"`
	Sets   []SetSnapshot   `json:"sets"`
}

// ChainSnapshot is one chain as the kernel holds it.
type ChainSnapshot struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	// Rules is how many rules the chain holds. nil means no number was read:
	// the chain is not there, or reading it failed and Err says so. A chain
	// can survive while its rules do not, so this is the number that says
	// whether the chain still does anything.
	Rules *int `json:"rules"`
	// Expected is what EnsureBase recorded after building the chain, so the
	// two can be put side by side. nil means this process never recorded it —
	// itself a finding, and the reason Verify refuses to pass without it.
	Expected *int   `json:"expected"`
	Err      string `json:"error,omitempty"`
}

// SetSnapshot is one set as the kernel holds it.
type SetSnapshot struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	// Elements is the kernel's own element count. nil means no number was
	// read: the set is not there, or reading it failed and Err says why. It is
	// never a stand-in for zero — telling those two apart is this type's
	// reason to exist. Interval sets store two elements per range, an
	// inclusive start and an exclusive end, so this is not the number of
	// ranges; Ranges is the readable view of the same contents.
	Elements  *int        `json:"elements"`
	Ranges    []RangeView `json:"ranges,omitempty"`
	Truncated bool        `json:"truncated"`
	Err       string      `json:"error,omitempty"`
}

// RangeView is one range as the kernel holds it.
type RangeView struct {
	// Prefix is set only when the range is exactly a CIDR block. The
	// coalescer legitimately produces ranges that are not one (see decompose),
	// and a fabricated /21 over a range that is not a /21 would be a lie in
	// the one view built to be believed.
	Prefix string `json:"prefix,omitempty"`
	From   string `json:"from"`
	To     string `json:"to"`
	// Expires is the element's remaining life as the kernel reports it. It can
	// disagree with the stored block's expiry; that disagreement is a finding,
	// not something to reconcile away on the way out.
	Expires *time.Time `json:"expires,omitempty"`
}

// Dump reads the kernel back through the backend. It is the read-only path the
// inspector uses, and it is on the service rather than handing the backend out
// because everything else on that interface writes.
func (s *Service) Dump(ctx context.Context) (Snapshot, error) { return s.backend.Dump(ctx) }

// Intent names the sets Skopos believes it has filled, so the inspector can put
// what the kernel holds beside what was meant to be in it. Without it an empty
// set reads as agreement: the 0.2.1 defect emptied four sets and left every one
// of them in place, and a view of the kernel alone would have shown that as a
// tidy row of zeroes.
func (s *Service) Intent(ctx context.Context) (map[string]bool, error) {
	return s.expectedNonEmpty(ctx)
}

// The rest of this file decodes what the kernel gives back into ranges a person
// can read. It lives here rather than beside the netlink code for the reason
// the address arithmetic in names.go does: it is the exact inverse of what was
// written, and it should build and be exercisable on every platform.

// maxRanges caps how many ranges one set renders. A single blocked country runs
// to tens of thousands of prefixes, which nobody reads and no browser should be
// asked to. The element count stays exact and Truncated says the list was cut.
const maxRanges = 2000

// elemBound is one set element lifted back into the orderable bound form
// intervalBounds writes: one byte wider than the address, so the end of a range
// that reaches the top of the family stays comparable with everything below it.
type elemBound struct {
	bound   []byte
	end     bool
	expires *time.Time
}

// startBound lifts an element key into bound form.
func startBound(key []byte) []byte { return append([]byte{0}, key...) }

// endBound is startBound for the exclusive end of a range, with the one case
// that matters: an all-zero key is how nftables spells "to the top of the
// family" (see setKey), so it lifts to one past the maximum address. Read
// literally it would be 0.0.0.0, and the range would render at the wrong end of
// the internet.
func endBound(key []byte) []byte {
	b := append([]byte{0}, key...)
	if allZero(key) {
		b[0] = 1
	}
	return b
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// prevBound returns the bound one below b: an exclusive end turned into the
// inclusive last address of the range it closes.
func prevBound(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i]--; out[i] != 0xff {
			break
		}
	}
	return out
}

// addrFromBound renders a bound as an address. It reports false for a bound
// that is not one — a caller holding one has mispaired something, and a guess
// rendered as an address is worse than a range left out.
func addrFromBound(b []byte) (netip.Addr, bool) {
	if len(b) < 2 || b[0] != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(b[1:])
}

// decodeRanges renders a set's elements. interval selects the pairing rule:
// interval sets store a start and an end per range, while the dev_* sets store
// one address per element and are not paired at all. It reports whether the
// list was cut short at maxRanges.
func decodeRanges(bounds []elemBound, interval bool) ([]RangeView, bool) {
	sort.Slice(bounds, func(i, j int) bool {
		if c := bytes.Compare(bounds[i].bound, bounds[j].bound); c != 0 {
			return c < 0
		}
		// At one key an end comes first: that is where one range stops and the
		// next begins. decompose emits exactly that pair whenever two adjacent
		// ranges carry different expiries, which is the common case for blocks.
		return bounds[i].end && !bounds[j].end
	})
	if interval {
		return pairRanges(bounds)
	}
	return singleAddrs(bounds)
}

// pairRanges walks sorted bounds and closes each start with the end that
// follows it.
func pairRanges(bounds []elemBound) ([]RangeView, bool) {
	out := make([]RangeView, 0, len(bounds)/2)
	var open *elemBound
	for i := range bounds {
		b := &bounds[i]
		if !b.end {
			open = b
			continue
		}
		if open == nil {
			// An end with nothing open, or a start with no end: the set holds
			// something this decoder did not write. Leaving it out is the only
			// honest option — its other half is the half that says how far it
			// reaches.
			continue
		}
		if v, ok := viewRange(open.bound, b.bound, open.expires); ok {
			out = append(out, v)
			if len(out) >= maxRanges {
				return out, true
			}
		}
		open = nil
	}
	return out, false
}

// singleAddrs renders the sets that hold plain addresses: From == To, no
// pairing.
func singleAddrs(bounds []elemBound) ([]RangeView, bool) {
	out := make([]RangeView, 0, len(bounds))
	for _, b := range bounds {
		a, ok := addrFromBound(b.bound)
		if !ok {
			continue
		}
		v := RangeView{From: a.String(), To: a.String(), Expires: b.expires}
		if p, ok := prefixOf(a, a); ok {
			v.Prefix = p.String()
		}
		out = append(out, v)
		if len(out) >= maxRanges {
			return out, true
		}
	}
	return out, false
}

// viewRange renders the half-open bound pair [lo, hi) the way a person reads a
// range.
func viewRange(lo, hi []byte, expires *time.Time) (RangeView, bool) {
	from, ok := addrFromBound(lo)
	if !ok {
		return RangeView{}, false
	}
	to, ok := addrFromBound(prevBound(hi))
	if !ok || from.BitLen() != to.BitLen() || to.Less(from) {
		return RangeView{}, false
	}
	v := RangeView{From: from.String(), To: to.String(), Expires: expires}
	if p, ok := prefixOf(from, to); ok {
		v.Prefix = p.String()
	}
	return v, true
}

// prefixView renders a prefix that is held as a prefix. Every stored rule is
// exactly a CIDR block, unlike what comes back out of the kernel, where the
// coalescer has already merged some of them into ranges that are not.
func prefixView(p netip.Prefix, expires *time.Time) (RangeView, bool) {
	if !p.IsValid() {
		return RangeView{}, false
	}
	p = p.Masked()
	return RangeView{
		Prefix:  p.String(),
		From:    p.Addr().String(),
		To:      lastAddr(p).String(),
		Expires: expires,
	}, true
}

// prefixOf reports the CIDR block a range is, when it is exactly one.
func prefixOf(from, to netip.Addr) (netip.Prefix, bool) {
	if !from.IsValid() || !to.IsValid() || from.BitLen() != to.BitLen() {
		return netip.Prefix{}, false
	}
	f, t := ipBytes(from), ipBytes(to)
	total := len(f) * 8
	// Count the low bits where from is all zeroes and to is all ones: that run
	// is the host part, if this range is a prefix at all.
	host := 0
	for i := total - 1; i >= 0; i-- {
		if f[i/8]>>(7-uint(i%8))&1 != 0 || t[i/8]>>(7-uint(i%8))&1 != 1 {
			break
		}
		host++
	}
	p := netip.PrefixFrom(from, total-host)
	if !p.IsValid() || p.Masked() != p || lastAddr(p) != to {
		return netip.Prefix{}, false
	}
	return p, true
}

// sortRules returns rules ordered by prefix then action, so equality checks
// and tests are deterministic.
func sortRules(rules []Rule) []Rule {
	out := append([]Rule(nil), rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix.String() != out[j].Prefix.String() {
			return out[i].Prefix.String() < out[j].Prefix.String()
		}
		return out[i].Action < out[j].Action
	})
	return out
}
