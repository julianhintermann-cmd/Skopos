// Package wol sends Wake-on-LAN magic packets so the dashboard can wake
// sleeping machines. A magic packet is 6 bytes of 0xFF followed by the target
// MAC repeated 16 times, broadcast as UDP; the NIC's standby logic matches on
// the payload, so port and addressing are conventions, not requirements.
package wol

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Packet builds the magic packet for a 6-byte hardware address.
func Packet(hw net.HardwareAddr) ([]byte, error) {
	if len(hw) != 6 {
		return nil, fmt.Errorf("wol: need a 6-byte MAC, got %d bytes", len(hw))
	}
	pkt := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xFF)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, hw...)
	}
	return pkt, nil
}

// Wake parses mac and broadcasts its magic packet to UDP port 9. The socket is
// opened with SO_BROADCAST, which the net package does not set by itself.
func Wake(mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("wol: %w", err)
	}
	pkt, err := Packet(hw)
	if err != nil {
		return err
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return fmt.Errorf("wol: opening socket: %w", err)
	}
	defer func() { _ = pc.Close() }()

	if _, err := pc.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4bcast, Port: 9}); err != nil {
		return fmt.Errorf("wol: sending magic packet: %w", err)
	}
	return nil
}
