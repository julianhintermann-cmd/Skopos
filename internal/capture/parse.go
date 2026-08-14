// Package capture reads packets from the host's network interfaces and turns
// them into flow.Packet metadata. The header parser is platform-independent
// and hostile-input-safe (every field access is bounds-checked); the actual
// AF_PACKET socket lives behind a Linux build tag, with a stub elsewhere.
package capture

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// PayloadParsing selects which application-layer parsers are allowed to read
// a packet's payload.
//
// These are privacy switches, not performance knobs. Reading DNS questions and
// TLS server names out of a household's traffic is the most revealing thing
// Skopos does, and capture.dns/capture.sni were documented as governing it
// while both parsers ran unconditionally — someone who turned DNS off to stop
// recording which sites their family visits was recording them anyway. So the
// switch sits at the parser, not downstream of it: with DNS off the names are
// never lifted out of the packet, and there is nothing to filter, forget or
// leak later.
type PayloadParsing struct {
	// DNS allows DNS and mDNS answers to be read for address→name mappings.
	DNS bool
	// SNI allows TLS ClientHellos to be read for the server name and the
	// JA4 client fingerprint, which come from the same handshake.
	SNI bool
}

// payloadParsing is process-wide because every capture source in a process
// runs under one configuration, and atomic because it is set once at startup
// while the capture goroutines read it for every packet. It starts fully on so
// that a caller who never configures it — the parser is also a library — sees
// the parsing the function names promise.
var payloadParsing atomic.Pointer[PayloadParsing]

// SetPayloadParsing applies the capture.dns and capture.sni switches to every
// subsequent parse.
func SetPayloadParsing(p PayloadParsing) { payloadParsing.Store(&p) }

func currentPayloadParsing() PayloadParsing {
	if p := payloadParsing.Load(); p != nil {
		return *p
	}
	return PayloadParsing{DNS: true, SNI: true}
}

// EtherType values we care about.
const (
	etherIPv4 = 0x0800
	etherIPv6 = 0x86DD
	etherVLAN = 0x8100
	etherARP  = 0x0806
)

const (
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58
)

// ParseIPPacket parses a bare IP packet — no link-layer header — into a
// flow.Packet. Point-to-point links (VPN tunnels, PPP, 6in4) carry no Ethernet
// header at all, so frames from them have no MAC addresses and must not be
// read as if they had. How much of the payload is read is whatever
// SetPayloadParsing was last given.
func ParseIPPacket(pkt []byte, ts time.Time) (flow.Packet, bool) {
	return parseIPPacket(pkt, ts, currentPayloadParsing())
}

func parseIPPacket(pkt []byte, ts time.Time, pp PayloadParsing) (flow.Packet, bool) {
	if len(pkt) < 1 {
		return flow.Packet{}, false
	}
	p := flow.Packet{Time: ts, Size: uint64(len(pkt))}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4(pkt, p, pp)
	case 6:
		return parseIPv6(pkt, p, pp)
	default:
		return flow.Packet{}, false
	}
}

// ParseFrame parses one Ethernet frame into a flow.Packet. It returns ok=false
// for frames it cannot or does not need to turn into a flow (ARP, truncated,
// unsupported ethertype). It never panics on malformed input. How much of the
// payload is read is whatever SetPayloadParsing was last given.
func ParseFrame(frame []byte, ts time.Time) (flow.Packet, bool) {
	return parseFrame(frame, ts, currentPayloadParsing())
}

func parseFrame(frame []byte, ts time.Time, pp PayloadParsing) (flow.Packet, bool) {
	if len(frame) < 14 {
		return flow.Packet{}, false
	}
	dstMAC := macString(frame[0:6])
	srcMAC := macString(frame[6:12])
	etherType := binary.BigEndian.Uint16(frame[12:14])
	off := 14

	// Skip up to two stacked VLAN tags.
	for i := 0; i < 2 && etherType == etherVLAN; i++ {
		if len(frame) < off+4 {
			return flow.Packet{}, false
		}
		etherType = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}

	p := flow.Packet{Time: ts, Size: uint64(len(frame)), SrcMAC: srcMAC, DstMAC: dstMAC}

	switch etherType {
	case etherIPv4:
		return parseIPv4(frame[off:], p, pp)
	case etherIPv6:
		return parseIPv6(frame[off:], p, pp)
	default:
		// ARP and everything else are not flows.
		return flow.Packet{}, false
	}
}

func parseIPv4(b []byte, p flow.Packet, pp PayloadParsing) (flow.Packet, bool) {
	if len(b) < 20 {
		return flow.Packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return flow.Packet{}, false
	}
	proto := b[9]
	src, ok := netip.AddrFromSlice(b[12:16])
	if !ok {
		return flow.Packet{}, false
	}
	dst, ok := netip.AddrFromSlice(b[16:20])
	if !ok {
		return flow.Packet{}, false
	}
	p.SrcIP, p.DstIP = src, dst

	// Only the first fragment of a datagram carries the transport header. Every
	// later one is payload, and reading payload as if it were a TCP header is
	// not merely inaccurate — it is steerable from outside. Bytes 0-3 of
	// whatever is being transferred become "ports", and byte 13 becomes the TCP
	// flags, so anyone who can send fragments to this host decides which of them
	// Skopos reads as a fresh connection attempt, and the source address they
	// appear to come from is the one they wrote in the outer header. Those
	// apparent SYNs reach the rate, portscan and country detectors, and a
	// detector finding carries SuggestBlock. A stranger would be choosing who
	// this firewall shuts out.
	//
	// The bytes are real and stay counted. What is unknown is reported as
	// unknown: addresses and protocol from the IP header, no ports, no flags —
	// the same shape ICMP already has.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return laterFragment(proto, p)
	}
	return parseL4(b[ihl:], proto, p, pp)
}

// laterFragment records a fragment that arrived without a transport header.
func laterFragment(proto byte, p flow.Packet) (flow.Packet, bool) {
	switch proto {
	case ipProtoTCP:
		p.Proto = model.ProtoTCP
	case ipProtoUDP:
		p.Proto = model.ProtoUDP
	case ipProtoICMP:
		p.Proto = model.ProtoICMP
	default:
		return flow.Packet{}, false
	}
	return p, true
}

func parseIPv6(b []byte, p flow.Packet, pp PayloadParsing) (flow.Packet, bool) {
	if len(b) < 40 {
		return flow.Packet{}, false
	}
	next := b[6]
	src, ok := netip.AddrFromSlice(b[8:24])
	if !ok {
		return flow.Packet{}, false
	}
	dst, ok := netip.AddrFromSlice(b[24:40])
	if !ok {
		return flow.Packet{}, false
	}
	p.SrcIP, p.DstIP = src, dst

	// Walk a bounded number of extension headers to reach the transport one.
	rest := b[40:]
	for hops := 0; hops < 8; hops++ {
		switch next {
		case ipProtoTCP, ipProtoUDP, ipProtoICMPv6, ipProtoICMP:
			return parseL4(rest, next, p, pp)
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return flow.Packet{}, false
			}
			hdrLen := (int(rest[1]) + 1) * 8
			if len(rest) < hdrLen {
				return flow.Packet{}, false
			}
			next = rest[0]
			rest = rest[hdrLen:]
		default:
			return flow.Packet{}, false
		}
	}
	return flow.Packet{}, false
}

func parseL4(b []byte, proto byte, p flow.Packet, pp PayloadParsing) (flow.Packet, bool) {
	switch proto {
	case ipProtoTCP:
		if len(b) < 20 {
			return flow.Packet{}, false
		}
		p.Proto = model.ProtoTCP
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		flags := b[13]
		// SYN set, ACK clear => a fresh connection attempt.
		p.SYN = flags&0x02 != 0 && flags&0x10 == 0
		dataOff := int(b[12]>>4) * 4
		if dataOff >= 20 && dataOff < len(b) && (pp.DNS || pp.SNI) {
			p = enrichTCPPayload(b[dataOff:], p, pp)
		}
		return p, true
	case ipProtoUDP:
		if len(b) < 8 {
			return flow.Packet{}, false
		}
		p.Proto = model.ProtoUDP
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		if pp.DNS && (p.SrcPort == portDNS || p.SrcPort == portMDNS || p.DstPort == portMDNS) {
			p.Names = parseDNSNames(b[8:])
		}
		return p, true
	case ipProtoICMP, ipProtoICMPv6:
		p.Proto = model.ProtoICMP
		return p, true
	default:
		return flow.Packet{}, false
	}
}

// enrichTCPPayload reads what a TCP payload can tell us without keeping any
// connection state: a TLS ClientHello gives the server name and the client's
// JA4 fingerprint, DNS-over-TCP gives name mappings. Anything else is left
// untouched — payload bytes never leave this function, and each half is read
// only while its switch in pp allows it.
func enrichTCPPayload(payload []byte, p flow.Packet, pp PayloadParsing) flow.Packet {
	if p.SrcPort == portDNS || p.DstPort == portDNS {
		// DNS over TCP prefixes the message with a 2-byte length.
		if pp.DNS && len(payload) > 2 {
			p.Names = parseDNSNames(payload[2:])
		}
		return p
	}
	if !pp.SNI {
		return p
	}
	if hello, ok := parseClientHello(payload); ok {
		if hello.SNI != "" {
			p.DstName = hello.SNI
			p.Names = append(p.Names, flow.NameRecord{Addr: p.DstIP.Unmap(), Name: hello.SNI})
		}
		p.JA4 = hello.JA4
	}
	return p
}

// macString formats a link-layer address that identifies one device.
//
// Only individual (unicast) addresses do. The group bit in the first octet
// marks broadcast and multicast destinations — ff:ff:ff:ff:ff:ff for an ARP
// query or a subnet broadcast, 01:00:5e:… and 33:33:… for mDNS, SSDP and NDP.
// Those belong to no single machine, and the all-zero address is a
// placeholder. They come back empty so the device inventory skips them
// instead of filing "192.168.1.255 (ff:ff:ff:ff:ff:ff)" as a neighbour.
func macString(b []byte) string {
	const hex = "0123456789abcdef"
	if len(b) < 6 || b[0]&0x01 != 0 {
		return ""
	}
	if b[0]|b[1]|b[2]|b[3]|b[4]|b[5] == 0 {
		return ""
	}
	out := make([]byte, 0, 17)
	for i := 0; i < 6; i++ {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[b[i]>>4], hex[b[i]&0x0f])
	}
	return string(out)
}
