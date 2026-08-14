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
	shed    shed
}

// attempt is a single observed connection attempt.
type attempt struct {
	target netip.Addr
	port   uint16
	at     time.Time
}

// pair is the (target, port) an attempt was aimed at — the unit both
// thresholds count distinct values of.
type pair struct {
	target netip.Addr
	port   uint16
}

type scanState struct {
	attempts []attempt
	firedAt  time.Time // suppresses re-firing within one window
	last     time.Time // when this source was last heard from

	// Distinct counts, maintained as attempts enter and leave the window
	// rather than re-derived from the ring on every packet.
	//
	// Deriving them cost two fresh maps and up to maxAttempts iterations each,
	// per SYN, on the capture goroutine — and the firedAt early-return only
	// helped after something had fired. A SYN flood against one service is
	// exactly the shape that never fires: one target, one port, both counts
	// stuck at 1 forever, so the full 8192-operation walk ran on every single
	// packet while the sampler sat below its threshold and said nothing. These
	// hold the same numbers for O(1) per packet, at the cost of one map entry
	// per live (target, port) — which for the flood that motivated this is a
	// single entry, and for a wide scan is bounded by the attempt ring.
	live      map[pair]int       // live attempts per (target, port)
	portsOn   map[netip.Addr]int // distinct live ports per target
	targetsOn map[uint16]int     // distinct live targets per port
}

func newScanState() *scanState {
	return &scanState{
		live:      make(map[pair]int),
		portsOn:   make(map[netip.Addr]int),
		targetsOn: make(map[uint16]int),
	}
}

func (s *scanState) seenAt() time.Time { return s.last }

// track folds an attempt into the distinct counts.
func (s *scanState) track(a attempt) {
	k := pair{target: a.target, port: a.port}
	n := s.live[k]
	s.live[k] = n + 1
	if n == 0 {
		s.portsOn[a.target]++
		s.targetsOn[a.port]++
	}
}

// forget takes an attempt back out, once it has left the window or been pushed
// off the end of the ring. The counts must lose exactly what the ring loses or
// they drift away from the thresholds they feed.
func (s *scanState) forget(a attempt) {
	k := pair{target: a.target, port: a.port}
	if n := s.live[k]; n > 1 {
		s.live[k] = n - 1
		return
	}
	delete(s.live, k)
	if n := s.portsOn[a.target] - 1; n > 0 {
		s.portsOn[a.target] = n
	} else {
		delete(s.portsOn, a.target)
	}
	if n := s.targetsOn[a.port] - 1; n > 0 {
		s.targetsOn[a.port] = n
	} else {
		delete(s.targetsOn, a.port)
	}
}

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
		if !makeRoom(d.sources, now, d.cfg.Window, &d.shed) {
			return
		}
		st = newScanState()
		d.sources[p.SrcIP] = st
	}
	st.last = now
	a := attempt{target: p.DstIP, port: p.DstPort, at: now}
	st.attempts = append(st.attempts, a)
	st.track(a)
	if over := len(st.attempts) - d.maxAttempts; over > 0 {
		for _, old := range st.attempts[:over] {
			st.forget(old)
		}
		st.attempts = st.attempts[over:]
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

	if ports := st.portsOn[p.DstIP]; ports >= th.Ports {
		st.firedAt = now
		d.sink.Raise(d.finding(p.SrcIP, fmt.Sprintf("Vertical port scan of %s", p.DstIP),
			fmt.Sprintf("%d distinct ports on %s within %s", ports, p.DstIP, d.cfg.Window)))
		return
	}
	if targets := st.targetsOn[p.DstPort]; targets >= th.Targets {
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
		st.forget(st.attempts[i])
	}
	if i > 0 {
		// Reslice rather than compact to the front: append reclaims the
		// abandoned prefix the next time it has to grow, so this is constant
		// work instead of moving every surviving element on every packet.
		st.attempts = st.attempts[i:]
	}
}

// Shed reports the per-source scan state this detector has had to forget, and
// the sources it could not take on because the map was full of active ones.
// A climbing Untracked means scans are going unwatched.
func (d *Portscan) Shed() ShedStats { return d.shed.stats() }
