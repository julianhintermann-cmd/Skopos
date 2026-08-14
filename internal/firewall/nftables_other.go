//go:build !linux

package firewall

import (
	"context"
	"errors"
	"net/netip"
)

// unsupportedBackend stands in on non-Linux platforms. It always reports
// itself unavailable, so Skopos degrades to monitor-only there instead of
// failing to start — handy for developing the UI on macOS or Windows.
type unsupportedBackend struct{}

// NewNFTablesBackend returns a backend that is never available off Linux. It
// takes the LAN ranges the Linux one does so the non-Linux build actually
// compiles against the same call site.
func NewNFTablesBackend([]netip.Prefix) Backend { return &unsupportedBackend{} }

func (unsupportedBackend) Name() string                 { return "nftables (unsupported)" }
func (unsupportedBackend) Available() bool              { return false }
func (unsupportedBackend) Verify(context.Context) error { return nil }

func (unsupportedBackend) SetCounts(context.Context) (map[string]int, error) {
	return map[string]int{}, nil
}
func (unsupportedBackend) EnsureBase(context.Context) error                       { return nil }
func (unsupportedBackend) Reconcile(context.Context, []Rule) error                { return nil }
func (unsupportedBackend) ReconcileCountry(context.Context, []netip.Prefix) error { return nil }
func (unsupportedBackend) ReconcileDevices(context.Context, []DeviceRule) error   { return nil }

func (unsupportedBackend) ReconcileProtected(context.Context, []netip.Prefix) error { return nil }

// Dump implements Backend by refusing to describe a kernel it cannot read. An
// empty snapshot would render as a table that is gone and fourteen sets holding
// nothing — an alarm, and a false one, on a platform where there was never
// anything to hold.
func (unsupportedBackend) Dump(context.Context) (Snapshot, error) {
	return Snapshot{}, errors.New("there is no nftables on this platform, so nothing can be read back")
}
