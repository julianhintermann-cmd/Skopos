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

// Coverage records what the capture was doing during one interval. It is
// written on a heartbeat, not when packets arrive, and that independence is
// the whole point: the rollups write nothing for a minute with no traffic and
// nothing for a minute with no capture, so without this record the two are
// byte-identical in the database and a chart cannot tell "no traffic" from
// "no measurement".
type Coverage struct {
	// Bucket is the start of the interval, truncated to the finest resolution
	// (one minute). Coarser rollups accumulate from the same records.
	Bucket time.Time
	// SourcesTotal is how many capture sources were configured, SourcesUp how
	// many stayed alive for the whole interval. A two-NIC capture that loses
	// one is partial coverage — not whole, and not down.
	SourcesTotal int
	SourcesUp    int
	// ObservedPackets is the true, pre-sampling count: the sampler counts
	// every packet before it decides whether to drop it, so this is exact even
	// while sampling. KeptPackets is what survived. Their ratio is the
	// realized keep rate, which is what the stored byte counts are a fraction
	// of — and it beats the nominal rate, which can change sixty times inside
	// a one-minute bucket.
	ObservedPackets uint64
	KeptPackets     uint64
	// SecondsCovered is how many heartbeats landed in the interval, so the
	// minute Skopos started or stopped is honest about being partial instead
	// of being dropped or passed off as whole.
	SecondsCovered int
}

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

// BlockProvenance is the trail behind a block: who placed it, what was
// observed, and the record it can be followed back to. Reason says why in
// words; this says where that sentence came from.
type BlockProvenance struct {
	// Actor is who placed the block, as the call site could attest to it: an
	// operator's username, "detector", "config" for the static blocklist,
	// "notification" for a notification button. It is never inferred from the
	// origin or the reason — an actor guessed from context reads exactly like
	// one that was recorded.
	Actor string
	// Evidence is the observation the block rests on, in a form that can be
	// checked afterwards. Empty means none was recorded, not that none
	// existed: most paths have only the reason sentence, and repeating it here
	// would dress a sentence up as evidence.
	Evidence string
	// AlertID and IncidentID link to the records that caused the block. Zero
	// means no link was recorded. A non-zero id whose row is gone means the
	// alert aged out of retention, which is a different answer again.
	AlertID    int64
	IncidentID int64
}

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
	// Provenance is where this block came from. Nil means the row was written
	// before Skopos recorded provenance at all (migration 0012) and is silent
	// on who placed it — which is what it must say. Filling those rows in with
	// a plausible actor would put a fabricated attribution in the one record an
	// operator opens to answer "why is this blocked, and who did it".
	Provenance *BlockProvenance
}

// Expired reports whether the block's TTL has passed at time now.
func (b Block) Expired(now time.Time) bool {
	return b.Expires != nil && now.After(*b.Expires)
}

// Device is a host observed on the LAN.
type Device struct {
	ID  int64
	MAC string
	// IP and IP6 are the device's addresses, one per family. A dual-stack
	// machine is one device with two addresses, not two devices — and a
	// firewall rule that covers only one of them is not a rule at all.
	IP  netip.Addr
	IP6 netip.Addr
	// Label is an operator-assigned name. It is set only through the UI and is
	// never overwritten by capture, so it takes precedence over the discovered
	// hostname wherever a device needs a human-readable name.
	Label    string
	Hostname string
	Vendor   string
	// WatchPresence is the operator's opt-in to arrive/leave notifications for
	// this device; Present is the tracker's last known state.
	WatchPresence bool
	Present       bool
	// Policy restricts what this device may reach. Empty means unrestricted.
	Policy    DevicePolicy
	FirstSeen time.Time
	LastSeen  time.Time
}

// DevicePolicy is the per-device egress rule. The motivating case is an IoT
// gadget with no business on the internet: LANOnly confines it to the local
// network while leaving everything else untouched.
type DevicePolicy string

const (
	// PolicyOpen is the default: no per-device restriction.
	PolicyOpen DevicePolicy = ""
	// PolicyLANOnly drops this device's traffic to and from the internet,
	// leaving local traffic alone.
	PolicyLANOnly DevicePolicy = "lan_only"
	// PolicyQuarantine drops all of this device's traffic in both
	// directions, local included — the "unplug it without walking over"
	// switch for a compromised machine.
	PolicyQuarantine DevicePolicy = "quarantine"
)

// Valid reports whether p is a known policy.
func (p DevicePolicy) Valid() bool {
	switch p {
	case PolicyOpen, PolicyLANOnly, PolicyQuarantine:
		return true
	}
	return false
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

// PrimaryAddr is the address that stands for the device wherever exactly one
// is needed — its traffic history, for instance. IPv4 wins: on a home network
// it is the address the operator recognises, and the rollups are keyed by it.
func (d Device) PrimaryAddr() netip.Addr {
	if d.IP.IsValid() {
		return d.IP
	}
	return d.IP6
}

// Addrs returns every address the device is known by, for the places that must
// cover all of them — blocking a quarantined device that still has a working
// IPv6 path is not a quarantine.
func (d Device) Addrs() []netip.Addr {
	var out []netip.Addr
	if d.IP.IsValid() {
		out = append(out, d.IP)
	}
	if d.IP6.IsValid() {
		out = append(out, d.IP6)
	}
	return out
}

// CFZone is a Cloudflare zone (a domain) the operator has connected, plus
// whether Skopos is actively monitoring its traffic. The list and the
// monitored flags are persisted so they survive a restart; the API token that
// backs them is sealed separately and never stored here in the clear.
type CFZone struct {
	ID        string
	Name      string
	Status    string
	Monitored bool
	Added     time.Time
}

// SpeedtestResult is one internet speed measurement.
type SpeedtestResult struct {
	ID        int64
	Time      time.Time
	DownMbps  float64
	UpMbps    float64
	LatencyMs float64
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
