package capture

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// build helpers ---------------------------------------------------------------

func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14)
	// dst MAC 02:02:03:04:05:06, src MAC aa:bb:cc:dd:ee:ff — both individual
	// addresses, since group addresses deliberately parse to no MAC at all.
	copy(f[0:6], []byte{2, 2, 3, 4, 5, 6})
	copy(f[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

func ipv4(proto byte, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	h[9] = proto
	copy(h[12:16], []byte{192, 168, 1, 10})
	copy(h[16:20], []byte{9, 9, 9, 9})
	return append(h, l4...)
}

func tcp(srcPort, dstPort uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[12] = 0x50 // data offset 5
	h[13] = flags
	return h
}

func udp(srcPort, dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	return h
}

// tests -----------------------------------------------------------------------

func TestParseIPv4TCPSYN(t *testing.T) {
	frame := ethFrame(etherIPv4, ipv4(ipProtoTCP, tcp(40000, 443, 0x02)))
	p, ok := ParseFrame(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.SrcIP.String() != "192.168.1.10" || p.DstIP.String() != "9.9.9.9" {
		t.Errorf("addrs = %s → %s", p.SrcIP, p.DstIP)
	}
	if p.SrcPort != 40000 || p.DstPort != 443 {
		t.Errorf("ports = %d → %d", p.SrcPort, p.DstPort)
	}
	if p.Proto != model.ProtoTCP {
		t.Errorf("proto = %s, want tcp", p.Proto)
	}
	if !p.SYN {
		t.Error("SYN flag should be set for SYN without ACK")
	}
	if p.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("src MAC = %s", p.SrcMAC)
	}
}

func TestParseSYNACKNotConnectionAttempt(t *testing.T) {
	frame := ethFrame(etherIPv4, ipv4(ipProtoTCP, tcp(443, 40000, 0x12))) // SYN+ACK
	p, ok := ParseFrame(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.SYN {
		t.Error("SYN+ACK must not count as a connection attempt")
	}
}

func TestParseUDP(t *testing.T) {
	frame := ethFrame(etherIPv4, ipv4(ipProtoUDP, udp(1234, 53)))
	p, ok := ParseFrame(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("expected parse ok")
	}
	if p.Proto != model.ProtoUDP || p.DstPort != 53 {
		t.Errorf("got proto=%s dport=%d", p.Proto, p.DstPort)
	}
}

func TestParseVLANTagged(t *testing.T) {
	// One 802.1Q tag: ethertype VLAN, then tag (4 bytes: pcp/vid + inner type).
	inner := ipv4(ipProtoTCP, tcp(40000, 22, 0x02))
	tag := make([]byte, 4)
	binary.BigEndian.PutUint16(tag[2:4], etherIPv4)
	frame := ethFrame(etherVLAN, append(tag, inner...))
	p, ok := ParseFrame(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("expected parse ok through VLAN tag")
	}
	if p.DstPort != 22 {
		t.Errorf("dport = %d, want 22", p.DstPort)
	}
}

func TestParseIPv6TCP(t *testing.T) {
	l4 := tcp(5000, 443, 0x02)
	h := make([]byte, 40)
	h[0] = 0x60 // version 6
	h[6] = ipProtoTCP
	// src fe80::1, dst 2606:4700::1111
	copy(h[8:24], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(h[24:40], []byte{0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11})
	frame := ethFrame(etherIPv6, append(h, l4...))
	p, ok := ParseFrame(frame, time.Unix(1, 0))
	if !ok {
		t.Fatal("expected IPv6 parse ok")
	}
	if p.Proto != model.ProtoTCP || p.DstPort != 443 {
		t.Errorf("got proto=%s dport=%d", p.Proto, p.DstPort)
	}
	if !p.SrcIP.Is6() {
		t.Errorf("src should be v6: %s", p.SrcIP)
	}
}

func TestParseRejectsGarbageWithoutPanic(t *testing.T) {
	// Fuzz-lite: a range of truncated/garbage frames must return ok=false and
	// never panic.
	inputs := [][]byte{
		nil,
		{1, 2, 3},
		ethFrame(etherIPv4, []byte{0x45}), // truncated IP
		ethFrame(etherIPv4, ipv4(ipProtoTCP, nil)), // IP ok, no L4
		ethFrame(etherARP, []byte{0, 1, 2, 3}),     // ARP: not a flow
		ethFrame(etherVLAN, []byte{0, 0}),          // truncated VLAN
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			if _, ok := ParseFrame(in, time.Unix(1, 0)); ok {
				t.Errorf("input %d unexpectedly parsed ok", i)
			}
		}()
	}
}

func TestMACStringRejectsGroupAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"unicast", []byte{0x6c, 0x1f, 0xf7, 0x92, 0x77, 0x71}, "6c:1f:f7:92:77:71"},
		{"locally administered unicast", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x20}, "de:ad:be:ef:00:20"},
		{"broadcast", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ""},
		{"ipv4 multicast", []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, ""},
		{"ipv6 multicast", []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}, ""},
		{"spanning tree", []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, ""},
		{"all zero", []byte{0, 0, 0, 0, 0, 0}, ""},
		{"short", []byte{0x6c, 0x1f}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := macString(tc.in); got != tc.want {
				t.Errorf("macString(%x) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Tunnels, PPP links and 6in4 interfaces deliver bare IP packets. Reading the
// first fourteen bytes of those as an Ethernet header invents MAC addresses.
func TestParseIPPacketHasNoMACs(t *testing.T) {
	pkt, ok := ParseIPPacket(ipv4(ipProtoTCP, tcp(1234, 443, 0x02)), time.Unix(0, 0))
	if !ok {
		t.Fatal("bare IPv4 packet should parse")
	}
	if pkt.SrcIP.String() != "192.168.1.10" || pkt.DstIP.String() != "9.9.9.9" {
		t.Errorf("addresses = %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.SrcMAC != "" || pkt.DstMAC != "" {
		t.Errorf("a link without an Ethernet header has no MACs, got %q/%q", pkt.SrcMAC, pkt.DstMAC)
	}
	if pkt.DstPort != 443 {
		t.Errorf("dst port = %d, want 443", pkt.DstPort)
	}
}

func TestParseIPPacketRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0x00}, {0xff, 0xff, 0xff}} {
		if _, ok := ParseIPPacket(in, time.Unix(0, 0)); ok {
			t.Errorf("ParseIPPacket(%x) should not parse", in)
		}
	}
}
