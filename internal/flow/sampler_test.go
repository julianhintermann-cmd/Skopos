package flow

import (
	"testing"
	"time"
)

func TestSamplerDisabledKeepsAll(t *testing.T) {
	s := NewSampler(0, nil)
	for i := 0; i < 1000; i++ {
		if !s.Keep() {
			t.Fatal("disabled sampler must keep every packet")
		}
	}
}

func TestSamplerBelowThresholdKeepsAll(t *testing.T) {
	s := NewSampler(10000, nil)
	// Simulate 5000 packets in one second — below the 10k threshold.
	for i := 0; i < 5000; i++ {
		s.Keep()
	}
	s.Measure(time.Second)
	if st := s.State(); st.Sampling {
		t.Errorf("should not sample at %d pps below threshold", st.ObservedPPS)
	}
	for i := 0; i < 100; i++ {
		if !s.Keep() {
			t.Fatal("below threshold, all packets must be kept")
		}
	}
}

func TestSamplerAboveThresholdSamplesAndReports(t *testing.T) {
	var transitions []SampleState
	s := NewSampler(1000, func(st SampleState) {
		transitions = append(transitions, st)
	})

	// 4000 packets in one second → 4x over threshold → keep ~1/4.
	for i := 0; i < 4000; i++ {
		s.Keep()
	}
	s.Measure(time.Second)

	st := s.State()
	if !st.Sampling {
		t.Fatal("should be sampling at 4000 pps over 1000 threshold")
	}
	if st.KeepRate > 0.3 || st.KeepRate < 0.2 {
		t.Errorf("keep rate = %.3f, want ~0.25", st.KeepRate)
	}
	if len(transitions) != 1 || !transitions[0].Sampling {
		t.Fatalf("expected exactly one transition into sampling, got %+v", transitions)
	}

	// Actually sampling: over many calls, roughly a quarter are kept.
	kept := 0
	const n = 4000
	for i := 0; i < n; i++ {
		if s.Keep() {
			kept++
		}
	}
	if kept > n/2 {
		t.Errorf("kept %d/%d while sampling, expected far fewer", kept, n)
	}

	// Drop back below threshold → must report the transition out.
	s.Measure(time.Second) // counter was ~4000 from the loop above... reset first
}

func TestSamplerReportsTransitionOut(t *testing.T) {
	var transitions []SampleState
	s := NewSampler(1000, func(st SampleState) {
		transitions = append(transitions, st)
	})

	for i := 0; i < 5000; i++ {
		s.Keep()
	}
	s.Measure(time.Second) // into sampling

	// Next window: quiet traffic, below threshold.
	for i := 0; i < 100; i++ {
		s.Keep()
	}
	s.Measure(time.Second) // out of sampling

	if len(transitions) != 2 {
		t.Fatalf("expected 2 transitions (in, out), got %d: %+v", len(transitions), transitions)
	}
	if transitions[0].Sampling == transitions[1].Sampling {
		t.Error("transitions should alternate in/out")
	}
	if st := s.State(); st.Sampling {
		t.Error("should be back to keeping all after quiet window")
	}
}
