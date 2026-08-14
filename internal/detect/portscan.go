package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Thresholds are the port-scan trigger levels within the window.
type Thresholds struct {
	Ports   int // distinct ports on one target ⇒ vertical scan
	Targets int // distinct targets on one port ⇒ horizontal scan
}

// PortscanConfig configures the detector.
type PortscanConfig struct {
	Window   time.Duration
	External Thresholds
	Internal Thresholds
	Severity model.Severity
	Block    bool
	// IsInternal reports whether an address is inside the private ranges, so
	// the detector can apply the right threshold set. Required.
	IsInternal func(netip.Addr) bool
}

// Portscan detects vertical scans (many ports on one target) and horizontal
// scans (one port across many targets) by watching TCP connection attempts
// (SYN without ACK) from each source within a sliding window.
type Portscan struct {
	cfg         PortscanConfig
	sink        Sink
	clock       Clock
	isPriv      func(netip.Addr) bool
	maxAttempts int

	mu      sync.Mutex
	sources map[netip.Addr]*scanState
}

// attempt is a single observed connection attempt.
type attempt struct {
	target netip.Addr
	port   uint16
	at     time.Time
}

type scanState struct {
	attempts []attempt
	firedAt  time.Time // suppresses re-firing within one window
	last     time.Time // when this source was last heard from
}

func (s *scanState) seenAt() time.Time { return s.last }

// SetThresholds swaps the detector's window and trigger counts at runtime.
// Guarded by the same mutex the packet path already takes, so a change lands
// between packets rather than mid-evaluation.
func (d *Portscan) SetThresholds(window time.Duration, external, internal Thresholds, block bool) {
	if window <= 0 {
		window = time.Minute
	}
	d.mu.Lock()
	d.cfg.Window = window
	d.cfg.External = external
	d.cfg.Internal = internal
	d.cfg.Block = block
	d.mu.Unlock()
}

// NewPortscan creates a port-scan detector.
func NewPortscan(cfg PortscanConfig, sink Sink, clock Clock) *Portscan {
	if clock == nil {
		clock = time.Now
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	isPriv := cfg.IsInternal
	if isPriv == nil {
		isPriv = func(netip.Addr) bool { return false }
	}
	return &Portscan{
		cfg:         cfg,
		sink:        sink,
		clock:       clock,
		isPriv:      isPriv,
		maxAttempts: 4096, // cap per-source memory under a sustained scan
		sources:     make(map[netip.Addr]*scanState),
	}
}

// Observe implements flow.Observer. Only fresh TCP connection attempts matter
// for scan detection.
func (d *Portscan) Observe(p flow.Packet) {
	if p.Proto != model.ProtoTCP || !p.SYN {
		return
	}
	now := p.Time
	if now.IsZero() {
		now = d.clock()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	st := d.sources[p.SrcIP]
	if st == nil {
		if !makeRoom(d.sources, now, d.cfg.Window) {
			return
		}
		st = &scanState{}
		d.sources[p.SrcIP] = st
	}
	st.last = now
	st.attempts = append(st.attempts, attempt{target: p.DstIP, port: p.DstPort, at: now})
	if len(st.attempts) > d.maxAttempts {
		st.attempts = st.attempts[len(st.attempts)-d.maxAttempts:]
	}
	d.prune(st, now)

	// One finding per source per window: don't re-fire while the previous
	// episode is still inside the window.
	if !st.firedAt.IsZero() && now.Sub(st.firedAt) < d.cfg.Window {
		return
	}

	th := d.cfg.External
	if d.isPriv(p.SrcIP) {
		th = d.cfg.Internal
	}

	if ports := distinctPortsOn(st.attempts, p.DstIP); ports >= th.Ports {
		st.firedAt = now
		d.sink.Raise(d.finding(p.SrcIP, fmt.Sprintf("Vertical port scan of %s", p.DstIP),
			fmt.Sprintf("%d distinct ports on %s within %s", ports, p.DstIP, d.cfg.Window)))
		return
	}
	if targets := distinctTargetsOn(st.attempts, p.DstPort); targets >= th.Targets {
		st.firedAt = now
		d.sink.Raise(d.finding(p.SrcIP, fmt.Sprintf("Horizontal scan on port %d", p.DstPort),
			fmt.Sprintf("%d distinct targets on port %d within %s", targets, p.DstPort, d.cfg.Window)))
	}
}

func (d *Portscan) finding(src netip.Addr, title, detail string) Finding {
	return Finding{
		Detector: "portscan", Source: src, Severity: d.cfg.Severity,
		Title: title, Detail: detail, SuggestBlock: d.cfg.Block,
	}
}

func (d *Portscan) prune(st *scanState, now time.Time) {
	cutoff := now.Add(-d.cfg.Window)
	i := 0
	for ; i < len(st.attempts); i++ {
		if st.attempts[i].at.After(cutoff) {
			break
		}
	}
	if i > 0 {
		// Reslice rather than compact to the front: append reclaims the
		// abandoned prefix the next time it has to grow, so this is constant
		// work instead of moving every surviving element on every packet.
		st.attempts = st.attempts[i:]
	}
}

func distinctPortsOn(attempts []attempt, target netip.Addr) int {
	seen := make(map[uint16]struct{})
	for _, a := range attempts {
		if a.target == target {
			seen[a.port] = struct{}{}
		}
	}
	return len(seen)
}

func distinctTargetsOn(attempts []attempt, port uint16) int {
	seen := make(map[netip.Addr]struct{})
	for _, a := range attempts {
		if a.port == port {
			seen[a.target] = struct{}{}
		}
	}
	return len(seen)
}
