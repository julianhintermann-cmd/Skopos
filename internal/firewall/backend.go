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

// Backend is the kernel abstraction. Implementations must be idempotent:
// EnsureBase can be called on every start, and Reconcile makes the kernel's
// block set exactly match desired, adding and removing as needed.
type Backend interface {
	// EnsureBase creates the table, chains and sets if absent.
	EnsureBase(ctx context.Context) error
	// Reconcile makes the enforced rule set exactly equal to desired.
	Reconcile(ctx context.Context, desired []Rule) error
	// Available reports whether the backend can actually enforce (required
	// capabilities and kernel support present).
	Available() bool
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
