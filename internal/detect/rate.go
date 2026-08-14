package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// RateConfig configures the rate/flood detector.
type RateConfig struct {
	Window              time.Duration
	MaxNewConnections   int // new TCP connection attempts per source per window
	MaxPacketsPerSecond int // sustained packet rate per source
	Severity            model.Severity
	Block               bool
}

// Rate detects connection floods and abnormal packet rates from a single
// source within a sliding window.
type Rate struct {
	cfg   RateConfig
	sink  Sink
	clock Clock

	mu      sync.Mutex
	sources map[netip.Addr]*rateState
}

type rateState struct {
	conns   rateWindow // new connection attempts
	packets rateWindow // every packet
	firedAt time.Time
	last    time.Time // when this source was last heard from
}

func (s *rateState) seenAt() time.Time { return s.last }

// rateBuckets is how finely the sliding window is divided. Twelve gives a
// window edge that moves in steps of a twelfth of the window — smooth enough
// that a burst is not double-counted across the boundary, coarse enough to
// stay tiny.
const rateBuckets = 12

// rateWindow counts events over a sliding window with a fixed-size ring of
// buckets.
//
// It used to be a slice of timestamps, one per packet. At the shipped default
// of 8000 packets per second over a ten-second window that is eighty thousand
// timestamps per source, re-compacted to the front of the slice on every
// single packet — quadratic work that could not keep up with the very rate it
// was configured to detect. Counting into buckets is constant work and
// constant memory, and a rate never needed the individual timestamps anyway.
type rateWindow struct {
	counts [rateBuckets]int
	head   int       // index of the newest bucket
	headAt time.Time // when the newest bucket started
	total  int
}

// add records n events at now and returns the total over the window.
func (w *rateWindow) add(now time.Time, window time.Duration, n int) int {
	step := window / rateBuckets
	if step <= 0 {
		step = time.Millisecond
	}
	switch {
	case w.headAt.IsZero():
		w.headAt = now
	case now.Before(w.headAt):
		// Clock went backwards, or packets arrived out of order by less than
		// a bucket. Count them in the current bucket rather than rewinding.
	default:
		advance := int(now.Sub(w.headAt) / step)
		if advance >= rateBuckets {
			// Nothing in the ring is still inside the window.
			*w = rateWindow{headAt: now}
		} else {
			for i := 0; i < advance; i++ {
				w.head = (w.head + 1) % rateBuckets
				w.total -= w.counts[w.head]
				w.counts[w.head] = 0
			}
			w.headAt = w.headAt.Add(time.Duration(advance) * step)
		}
	}
	w.counts[w.head] += n
	w.total += n
	return w.total
}

// NewRate creates a rate detector.
func NewRate(cfg RateConfig, sink Sink, clock Clock) *Rate {
	if clock == nil {
		clock = time.Now
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Second
	}
	return &Rate{cfg: cfg, sink: sink, clock: clock, sources: make(map[netip.Addr]*rateState)}
}

// SetLimits swaps the detector's window and limits at runtime, under the same
// mutex the packet path takes.
func (d *Rate) SetLimits(window time.Duration, maxConns, maxPPS int, block bool) {
	if window <= 0 {
		window = 10 * time.Second
	}
	d.mu.Lock()
	d.cfg.Window = window
	d.cfg.MaxNewConnections = maxConns
	d.cfg.MaxPacketsPerSecond = maxPPS
	d.cfg.Block = block
	d.mu.Unlock()
}

// Observe implements flow.Observer.
func (d *Rate) Observe(p flow.Packet) {
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
		st = &rateState{}
		d.sources[p.SrcIP] = st
	}
	st.last = now
	packets := st.packets.add(now, d.cfg.Window, 1)
	// Adding zero still slides the window, so a source that stops opening
	// connections stops counting as if it had.
	newConn := 0
	if p.Proto == model.ProtoTCP && p.SYN {
		newConn = 1
	}
	conns := st.conns.add(now, d.cfg.Window, newConn)

	if !st.firedAt.IsZero() && now.Sub(st.firedAt) < d.cfg.Window {
		return
	}

	if d.cfg.MaxNewConnections > 0 && conns >= d.cfg.MaxNewConnections {
		st.firedAt = now
		d.sink.Raise(d.finding(p.SrcIP, "Connection-rate spike",
			fmt.Sprintf("%d new connections within %s", conns, d.cfg.Window)))
		return
	}
	if d.cfg.MaxPacketsPerSecond > 0 {
		pps := float64(packets) / d.cfg.Window.Seconds()
		if int(pps) >= d.cfg.MaxPacketsPerSecond {
			st.firedAt = now
			d.sink.Raise(d.finding(p.SrcIP, "Packet-rate spike",
				fmt.Sprintf("~%d packets/s sustained over %s", int(pps), d.cfg.Window)))
		}
	}
}

func (d *Rate) finding(src netip.Addr, title, detail string) Finding {
	return Finding{
		Detector: "rate", Source: src, Severity: d.cfg.Severity,
		Title: title, Detail: detail, SuggestBlock: d.cfg.Block,
	}
}
