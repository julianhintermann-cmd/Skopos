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
	m.mu.Unlock()
}

// Snapshot implements api.LiveProvider. It computes the average rate since the
// previous call, which matches the dashboard's 1–2 s poll cadence.
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
	}

	st := api.LiveStats{BitsPerSecond: m.bps, PacketsPerSecond: m.pps}
	if m.samp != nil {
		s := m.samp()
		st.Sampling = s.Sampling
		st.ObservedPPS = s.ObservedPPS
	}
	return st
}
