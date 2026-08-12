//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// afpacketSource captures from a single interface using an AF_PACKET raw
// socket. It reads whole frames into a reusable buffer and parses only the
// headers — payloads are never copied out. Requires CAP_NET_RAW.
type afpacketSource struct {
	iface   string
	snaplen int
}

// NewInterfaceSource creates a live capture source for one interface. It is
// only available on Linux; other platforms get a stub that errors.
func NewInterfaceSource(iface string) Source {
	return &afpacketSource{iface: iface, snaplen: 2048}
}

func (s *afpacketSource) Name() string { return "afpacket:" + s.iface }

func (s *afpacketSource) Run(ctx context.Context, handle func(flow.Packet)) error {
	ifi, err := net.InterfaceByName(s.iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", s.iface, err)
	}

	// ETH_P_ALL in network byte order; SOCK_RAW gives us full frames.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("opening AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		return fmt.Errorf("binding to %q: %w", s.iface, err)
	}

	// A read timeout lets us notice context cancellation between frames.
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, s.snaplen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue // timeout or interrupt: re-check ctx and read again
			}
			return fmt.Errorf("reading from %q: %w", s.iface, err)
		}
		if n <= 0 {
			continue
		}
		if p, ok := ParseFrame(buf[:n], time.Now()); ok {
			handle(p)
		}
	}
}

// htons converts a uint16 to network byte order.
func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }
