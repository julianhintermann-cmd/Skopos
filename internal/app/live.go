package app

import (
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// liveMeter tracks a rolling estimate of current throughput for the overview
// and stream. It implements flow.Observer (to count every packet) and
// api.LiveProvider (to report the rate).
type liveMeter struct {
	clock func() time.Time
	samp  func() flow.SampleState

	mu        sync.Mutex
	bytes     uint64
	packets   uint64
	lastAt    time.Time
	lastBytes uint64
	lastPkts  uint64
	bps, pps  float64
	measured  bool
	// lastPacket is when a packet last arrived, which is not the same clock as
	// lastAt — that one only says when Snapshot was called. Reporting it is
	// what lets a surface distinguish a network that has gone quiet from a
	// capture that has stopped.
	lastPacket time.Time
}

func newLiveMeter(clock func() time.Time, samp func() flow.SampleState) *liveMeter {
	if clock == nil {
		clock = time.Now
	}
	return &liveMeter{clock: clock, samp: samp, lastAt: clock()}
}

// Observe implements flow.Observer.
func (m *liveMeter) Observe(p flow.Packet) {
	m.mu.Lock()
	m.bytes += p.Size
	m.packets++
	// The packet already carries its timestamp, so this costs no clock call on
	// the hot path and the mutex is held either way.
	m.lastPacket = p.Time
	m.mu.Unlock()
}

// Snapshot implements api.LiveProvider. It computes the average rate since the
// previous call, which matches the dashboard's 1–2 s poll cadence.
//
// The rate is reported only when the capture is known to be running. When it
// is not, the same computation yields exactly 0.0 — bytes minus lastBytes over
// elapsed — and a dead capture and a silent network became the same four
// numbers, rendered in the accent colour as though measured. The fields are
// omitted instead.
func (m *liveMeter) Snapshot() api.LiveStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	elapsed := now.Sub(m.lastAt).Seconds()
	if elapsed >= 0.2 {
		m.bps = float64(8*(m.bytes-m.lastBytes)) / elapsed
		m.pps = float64(m.packets-m.lastPkts) / elapsed
		m.lastAt = now
		m.lastBytes = m.bytes
		m.lastPkts = m.packets
		m.measured = true
	}

	measuredAt := now
	st := api.LiveStats{MeasuredAt: &measuredAt}
	if !m.lastPacket.IsZero() {
		last := m.lastPacket
		st.LastPacketAt = &last
	}

	var samp flow.SampleState
	if m.samp != nil {
		samp = m.samp()
	}
	if samp.Capture == "" {
		// No sampler wired: nothing is known about the capture, and a rate
		// cannot be qualified without knowing whether anything was listening.
		return st
	}
	st.Capture = string(samp.Capture)
	up, total := samp.SourcesUp, samp.SourcesTotal
	st.SourcesUp, st.SourcesTotal = &up, &total

	if samp.Capture != flow.CaptureUp && samp.Capture != flow.CapturePartial {
		return st
	}
	if m.measured {
		// Under sampling this counts only the packets that survived, so it is
		// a floor. KeepRate ships with it so the reader can derive the
		// estimate; the floor itself is never scaled here.
		bps, pps := m.bps, m.pps
		st.BitsPerSecond, st.PacketsPerSecond = &bps, &pps
	}
	st.Sampling = samp.Sampling
	observed, rate := samp.ObservedPPS, samp.KeepRate
	st.ObservedPPS, st.KeepRate = &observed, &rate
	return st
}
