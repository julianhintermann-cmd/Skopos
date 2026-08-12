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
	conns   []time.Time // connection-attempt timestamps
	packets []time.Time // all packet timestamps
	firedAt time.Time
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
		st = &rateState{}
		d.sources[p.SrcIP] = st
	}
	st.packets = append(st.packets, now)
	if p.Proto == model.ProtoTCP && p.SYN {
		st.conns = append(st.conns, now)
	}
	st.packets = pruneTimes(st.packets, now.Add(-d.cfg.Window))
	st.conns = pruneTimes(st.conns, now.Add(-d.cfg.Window))

	if !st.firedAt.IsZero() && now.Sub(st.firedAt) < d.cfg.Window {
		return
	}

	if d.cfg.MaxNewConnections > 0 && len(st.conns) >= d.cfg.MaxNewConnections {
		st.firedAt = now
		d.sink.Raise(d.finding(p.SrcIP, "Connection-rate spike",
			fmt.Sprintf("%d new connections within %s", len(st.conns), d.cfg.Window)))
		return
	}
	if d.cfg.MaxPacketsPerSecond > 0 {
		pps := float64(len(st.packets)) / d.cfg.Window.Seconds()
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

// pruneTimes drops timestamps at or before cutoff, preserving order.
func pruneTimes(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for ; i < len(times); i++ {
		if times[i].After(cutoff) {
			break
		}
	}
	if i > 0 {
		return append(times[:0], times[i:]...)
	}
	return times
}
