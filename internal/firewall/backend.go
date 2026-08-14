// Package firewall applies and reconciles IP blocks. The store holds the
// desired state (active blocks); a Backend drives the kernel toward it. In v1
// the only real backend is nftables; a memory backend backs the tests and a
// monitor-only backend keeps Skopos running when the kernel cannot enforce.
package firewall

import (
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
	// Name identifies the backend for logs and the system view.
	Name() string
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
