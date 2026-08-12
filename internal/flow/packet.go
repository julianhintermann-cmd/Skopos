// Package flow turns a stream of observed packets into aggregated flow
// records. It owns the packet-metadata type that capture sources emit, the
// 5-tuple aggregator that batches flows for the store and detectors, address
// classification against the configured private ranges, and adaptive
// sampling under load.
package flow

import (
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Packet is the minimal metadata a capture source extracts from one frame.
// Payloads are never carried here — only headers and, where enabled, parsed
// names. This is the single boundary type between capture and aggregation.
type Packet struct {
	Time    time.Time
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   model.Protocol
	Size    uint64 // total on-wire bytes of the frame
	SYN     bool   // TCP SYN without ACK — a connection attempt
	// Link-layer identity of the local endpoint, when observed, for the
	// device inventory. Empty for routed/WAN packets.
	SrcMAC string
	DstMAC string
	// Optional parsed name for the destination (DNS answer / TLS SNI).
	DstName string
}

// key identifies a flow: a canonical 5-tuple. Flows are unidirectional; the
// aggregator pairs the two directions by also tracking the reverse key.
type key struct {
	srcIP   netip.Addr
	dstIP   netip.Addr
	srcPort uint16
	dstPort uint16
	proto   model.Protocol
}

func (p Packet) key() key {
	return key{p.SrcIP, p.DstIP, p.SrcPort, p.DstPort, p.Proto}
}

func (k key) reverse() key {
	return key{k.dstIP, k.srcIP, k.dstPort, k.srcPort, k.proto}
}
