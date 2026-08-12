// Package model defines the domain types shared across Skopos: flows,
// alerts, blocks, devices and audit entries. Keeping them in one dependency-
// free package lets the store, detection, firewall, notification and API
// layers agree on shapes without importing one another.
package model

import (
	"net/netip"
	"time"
)

// Severity ranks how urgent an alert is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Rank returns an ordering value (higher = more severe), used for quiet-hours
// thresholds and sorting.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityCritical:
		return 3
	default:
		return 0
	}
}

// Direction classifies a flow relative to the configured private ranges.
type Direction string

const (
	DirLANtoWAN Direction = "lan_wan" // internal source, external destination
	DirWANtoLAN Direction = "wan_lan" // external source, internal destination
	DirLANtoLAN Direction = "lan_lan" // both endpoints internal
	DirWANtoWAN Direction = "wan_wan" // both external (rare; transit/misroute)
)

// Protocol is an IP transport protocol number kept as a small enum for the
// common cases.
type Protocol uint8

const (
	ProtoTCP  Protocol = 6
	ProtoUDP  Protocol = 17
	ProtoICMP Protocol = 1
)

func (p Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return "other"
	}
}

// Flow is an aggregated network conversation over a short interval: a 5-tuple
// with byte and packet counters per direction. Individual packets are never
// stored; only these aggregates are.
type Flow struct {
	Start   time.Time
	End     time.Time
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   Protocol
	Dir     Direction
	// Counters are measured from the source's perspective; "in" is traffic
	// flowing back toward the source (i.e. destination → source).
	OutBytes   uint64
	OutPackets uint64
	InBytes    uint64
	InPackets  uint64
	// Optional enrichment (empty when disabled or unknown).
	DstName string // DNS/SNI hostname for the destination, if known
}

// Bytes is the total bytes in both directions.
func (f Flow) Bytes() uint64 { return f.OutBytes + f.InBytes }

// Packets is the total packets in both directions.
func (f Flow) Packets() uint64 { return f.OutPackets + f.InPackets }

// Alert is a raised detection event.
type Alert struct {
	ID       int64
	Time     time.Time
	Detector string // e.g. "portscan", "rate", "feeds", "new_device"
	Severity Severity
	Source   netip.Addr // the offending address, when applicable
	Title    string
	Detail   string
	Count    int  // number of aggregated occurrences (cooldown)
	Ack      bool // acknowledged in the UI
	AckTime  *time.Time
}

// BlockOrigin records who created a block.
type BlockOrigin string

const (
	OriginManual   BlockOrigin = "manual"
	OriginDetector BlockOrigin = "detector"
	OriginStatic   BlockOrigin = "static" // from firewall.blocklist in config
)

// Block is an active or historical firewall block of an address or CIDR.
type Block struct {
	ID        int64
	Prefix    netip.Prefix
	Origin    BlockOrigin
	Reason    string
	Created   time.Time
	Expires   *time.Time // nil = permanent
	Active    bool
	RemovedAt *time.Time
}

// Expired reports whether the block's TTL has passed at time now.
func (b Block) Expired(now time.Time) bool {
	return b.Expires != nil && now.After(*b.Expires)
}

// Device is a host observed on the LAN.
type Device struct {
	ID  int64
	MAC string
	IP  netip.Addr
	// Label is an operator-assigned name. It is set only through the UI and is
	// never overwritten by capture, so it takes precedence over the discovered
	// hostname wherever a device needs a human-readable name.
	Label     string
	Hostname  string
	Vendor    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Name is the best human-readable label for the device: the operator's label
// if set, otherwise the discovered hostname, otherwise the empty string (the
// UI renders that as "unknown").
func (d Device) Name() string {
	if d.Label != "" {
		return d.Label
	}
	return d.Hostname
}

// AuditEntry records a security-relevant action for the audit log.
type AuditEntry struct {
	ID     int64
	Time   time.Time
	Actor  string // "system", "admin", token name, …
	Action string // "block", "unblock", "login", "login_failed", …
	Target string // address, CIDR, username, …
	Detail string
}
