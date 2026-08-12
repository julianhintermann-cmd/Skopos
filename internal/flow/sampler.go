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

	mu        sync.Mutex
	windowPPS int     // observed rate in the last measured window
	rate      float64 // fraction kept (1.0 = keep all)
	sampling  bool

	counter atomic.Uint64 // packets seen since last measurement
	seq     atomic.Uint64 // monotonic counter used for deterministic sampling
}

// SampleState is reported on every sampling transition.
type SampleState struct {
	Sampling    bool
	ObservedPPS int
	KeepRate    float64
}

// NewSampler creates a Sampler. thresholdPPS <= 0 disables sampling entirely
// (Keep always returns true).
func NewSampler(thresholdPPS int, onChange func(SampleState)) *Sampler {
	return &Sampler{
		thresholdPPS: thresholdPPS,
		onChange:     onChange,
		rate:         1.0,
	}
}

// Keep reports whether the current packet should be processed. It is cheap and
// safe to call from the capture hot path.
func (s *Sampler) Keep() bool {
	s.counter.Add(1)
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

// measure recomputes the keep-rate from the packets seen since the last call
// and the elapsed time. It is called by Run once per window.
func (s *Sampler) measure(elapsed time.Duration) {
	seen := s.counter.Swap(0)
	if elapsed <= 0 {
		return
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
}

// State returns the current sampler state.
func (s *Sampler) State() SampleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SampleState{Sampling: s.sampling, ObservedPPS: s.windowPPS, KeepRate: s.rate}
}
