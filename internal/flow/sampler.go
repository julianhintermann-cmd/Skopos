package flow

import (
	"sync"
	"sync/atomic"
	"time"
)

// Sampler protects the NAS from being overwhelmed by a traffic flood: above a
// configured packet rate it starts dropping a deterministic fraction of
// packets so the capture and detection paths keep up. The important property
// is honesty — every transition into and out of sampling is surfaced through
// the OnChange callback so it is reported as an event, never silent.
type Sampler struct {
	thresholdPPS int
	onChange     func(SampleState)
	health       *CaptureHealth

	mu        sync.Mutex
	windowPPS int     // observed rate in the last measured window
	rate      float64 // fraction kept (1.0 = keep all)
	sampling  bool

	counter atomic.Uint64 // packets seen since last measurement
	kept    atomic.Uint64 // ...of which survived the drop decision
	seq     atomic.Uint64 // monotonic counter used for deterministic sampling
}

// SampleState is reported on every sampling transition, and is also how the
// live view learns what the capture is doing. Sampling and capture health
// travel together because neither means anything alone: a keep rate describes
// nothing if no source is running, and a rate of zero bits per second means
// one thing under a live capture and something else entirely under a dead one.
type SampleState struct {
	Sampling    bool
	ObservedPPS int
	KeepRate    float64
	// Capture, SourcesUp and SourcesTotal come from the source registry, not
	// from the packet counters — silence is never read as a fault.
	Capture      CaptureStatus
	SourcesUp    int
	SourcesTotal int
}

// Window is one measurement interval's packet counts. Both are exact: Keep
// counts every packet before it decides whether to drop it, so the
// pre-sampling total is known even during a flood. That is what lets a stored
// byte count carry its own keep rate instead of being silently a tenth of the
// truth.
type Window struct {
	Observed uint64
	Kept     uint64
	Elapsed  time.Duration
}

// NewSampler creates a Sampler. thresholdPPS <= 0 disables sampling entirely
// (Keep always returns true).
func NewSampler(thresholdPPS int, onChange func(SampleState)) *Sampler {
	return &Sampler{
		thresholdPPS: thresholdPPS,
		onChange:     onChange,
		health:       NewCaptureHealth(),
		rate:         1.0,
	}
}

// Health is the capture-source registry and coverage accumulator. The sampler
// carries it because it is the one object that sits on every packet and is
// handed to both the capture loop and the live view.
func (s *Sampler) Health() *CaptureHealth { return s.health }

// Keep reports whether the current packet should be processed. It is cheap and
// safe to call from the capture hot path.
func (s *Sampler) Keep() bool {
	s.counter.Add(1)
	if !s.decide() {
		return false
	}
	// Counting what survives, not only what arrived, is what makes the keep
	// rate a measurement rather than the nominal figure — the nominal one is
	// recomputed every second and can change sixty times inside one bucket.
	s.kept.Add(1)
	return true
}

func (s *Sampler) decide() bool {
	if s.thresholdPPS <= 0 {
		return true
	}
	s.mu.Lock()
	rate := s.rate
	s.mu.Unlock()
	if rate >= 1.0 {
		return true
	}
	// Deterministic 1-in-N sampling from a monotonic sequence: no RNG on the
	// hot path, even coverage, and reproducible in tests.
	n := s.seq.Add(1)
	step := uint64(1.0/rate + 0.5)
	if step < 1 {
		step = 1
	}
	return n%step == 0
}

// Measure recomputes the keep-rate from the packets seen since the last call
// and the elapsed time, and returns the window it just closed. The runtime
// calls it once per second and hands the window to the coverage heartbeat.
func (s *Sampler) Measure(elapsed time.Duration) Window {
	// Kept is swapped before observed so a packet caught between the two can
	// only be missing from Kept, never counted in Kept without its Observed.
	// The pair is read as a keep rate and must never exceed 1.
	kept := s.kept.Swap(0)
	seen := s.counter.Swap(0)
	w := Window{Observed: seen, Kept: kept, Elapsed: elapsed}
	if elapsed <= 0 {
		// The counts are still returned: they were measured, and dropping them
		// because the clock did not advance would lose packets silently.
		return w
	}
	pps := int(float64(seen) / elapsed.Seconds())

	s.mu.Lock()
	prevSampling := s.sampling
	s.windowPPS = pps
	if s.thresholdPPS > 0 && pps > s.thresholdPPS {
		s.rate = float64(s.thresholdPPS) / float64(pps)
		s.sampling = true
	} else {
		s.rate = 1.0
		s.sampling = false
	}
	state := SampleState{Sampling: s.sampling, ObservedPPS: pps, KeepRate: s.rate}
	changed := prevSampling != s.sampling
	s.mu.Unlock()

	if changed && s.onChange != nil {
		s.onChange(state)
	}
	return w
}

// State returns the current sampler state, with capture health folded in.
func (s *Sampler) State() SampleState {
	s.mu.Lock()
	st := SampleState{Sampling: s.sampling, ObservedPPS: s.windowPPS, KeepRate: s.rate}
	s.mu.Unlock()

	h := s.health.State()
	st.Capture, st.SourcesUp, st.SourcesTotal = h.Status, h.SourcesUp, h.SourcesTotal
	return st
}
