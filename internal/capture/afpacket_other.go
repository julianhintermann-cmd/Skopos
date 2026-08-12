//go:build !linux

package capture

import (
	"context"
	"errors"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// ErrUnsupported is returned by the live capture source on non-Linux
// platforms. Skopos still builds and runs there (with the demo source) so the
// UI can be developed on any OS.
var ErrUnsupported = errors.New("live packet capture requires Linux (AF_PACKET); use demo mode on this platform")

type unsupportedSource struct{ iface string }

// NewInterfaceSource returns a stub that errors when run: real capture is
// Linux-only.
func NewInterfaceSource(iface string) Source { return &unsupportedSource{iface: iface} }

func (s *unsupportedSource) Name() string { return "afpacket:" + s.iface + " (unsupported)" }

func (s *unsupportedSource) Run(context.Context, func(flow.Packet)) error {
	return ErrUnsupported
}
