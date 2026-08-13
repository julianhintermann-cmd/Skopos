//go:build !linux

package firewall

import (
	"context"
	"net/netip"
)

// unsupportedBackend stands in on non-Linux platforms. It always reports
// itself unavailable, so Skopos degrades to monitor-only there instead of
// failing to start — handy for developing the UI on macOS or Windows.
type unsupportedBackend struct{}

// NewNFTablesBackend returns a backend that is never available off Linux.
func NewNFTablesBackend() Backend { return &unsupportedBackend{} }

func (unsupportedBackend) Name() string                                           { return "nftables (unsupported)" }
func (unsupportedBackend) Available() bool                                        { return false }
func (unsupportedBackend) EnsureBase(context.Context) error                       { return nil }
func (unsupportedBackend) Reconcile(context.Context, []Rule) error                { return nil }
func (unsupportedBackend) ReconcileCountry(context.Context, []netip.Prefix) error { return nil }
func (unsupportedBackend) ReconcileDevices(context.Context, []DeviceRule) error   { return nil }
