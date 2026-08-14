package flow

import (
	"testing"
	"time"
)

func TestCaptureHealthReportsStarting(t *testing.T) {
	h := NewCaptureHealth()
	if st := h.State(); st.Status != CaptureStarting {
		t.Errorf("empty registry = %q, want %q", st.Status, CaptureStarting)
	}
	h.Register("afpacket:eth0")
	// Registered but not yet reporting is still starting, not down: a restart
	// must not raise a capture-failure alarm on every boot.
	if st := h.State(); st.Status != CaptureStarting {
		t.Errorf("registered-not-started = %q, want %q", st.Status, CaptureStarting)
	}
}

func TestCaptureHealthStatusTransitions(t *testing.T) {
	h := NewCaptureHealth()
	h.Register("a")
	h.Register("b")

	h.Up("a")
	if st := h.State(); st.Status != CapturePartial || st.SourcesUp != 1 || st.SourcesTotal != 2 {
		t.Errorf("one of two up = %+v, want partial 1/2", st)
	}
	h.Up("b")
	if st := h.State(); st.Status != CaptureUp {
		t.Errorf("both up = %q, want %q", st.Status, CaptureUp)
	}
	h.Down("a")
	h.Down("b")
	if st := h.State(); st.Status != CaptureDown || st.SourcesUp != 0 {
		t.Errorf("both down = %+v, want down 0/2", st)
	}
}

// The heartbeat runs on the clock, not on traffic. A minute with a live
// capture and no packets must still produce a coverage record — that record is
// the only thing separating a quiet network from a dead one.
func TestHeartbeatRecordsAQuietMinute(t *testing.T) {
	h := NewCaptureHealth()
	h.Register("eth0")
	h.Up("eth0")

	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 60; i++ {
		h.Tick(base.Add(time.Duration(i)*time.Second), Window{Elapsed: time.Second})
	}

	cov := h.Drain()
	if len(cov) != 1 {
		t.Fatalf("got %d coverage records for a quiet minute, want 1", len(cov))
	}
	c := cov[0]
	if c.SourcesUp != 1 || c.SourcesTotal != 1 {
		t.Errorf("sources = %d of %d, want 1 of 1", c.SourcesUp, c.SourcesTotal)
	}
	if c.SecondsCovered != 60 {
		t.Errorf("seconds_covered = %d, want 60", c.SecondsCovered)
	}
	if c.ObservedPackets != 0 {
		t.Errorf("observed = %d, want 0 — the minute really was quiet", c.ObservedPackets)
	}

	// The same minute with the source down must differ, or the two states are
	// still the same row.
	h.Down("eth0")
	h.Tick(base.Add(time.Minute), Window{Elapsed: time.Second})
	dead := h.Drain()
	if len(dead) != 1 {
		t.Fatalf("got %d records, want 1", len(dead))
	}
	if dead[0].SourcesUp == c.SourcesUp {
		t.Fatal("a quiet minute and a dead capture produced the same coverage record")
	}
}

// A source that drops mid-bucket makes the whole bucket partial: sources_up is
// the minimum across it, not an average that hides the outage.
func TestHeartbeatTakesTheMinimumSourceCount(t *testing.T) {
	h := NewCaptureHealth()
	h.Register("a")
	h.Register("b")
	h.Up("a")
	h.Up("b")

	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	h.Tick(base, Window{Elapsed: time.Second})
	h.Down("b")
	h.Tick(base.Add(time.Second), Window{Elapsed: time.Second})
	h.Up("b")
	h.Tick(base.Add(2*time.Second), Window{Elapsed: time.Second})

	cov := h.Drain()
	if len(cov) != 1 || cov[0].SourcesUp != 1 || cov[0].SourcesTotal != 2 {
		t.Fatalf("got %+v, want one bucket at 1 of 2 sources", cov)
	}
}

func TestHeartbeatSplitsAcrossBuckets(t *testing.T) {
	h := NewCaptureHealth()
	h.Register("eth0")
	h.Up("eth0")

	base := time.Date(2026, 8, 12, 10, 0, 30, 0, time.UTC)
	h.Tick(base, Window{Observed: 10, Kept: 10, Elapsed: time.Second})
	h.Tick(base.Add(time.Minute), Window{Observed: 20, Kept: 20, Elapsed: time.Second})

	cov := h.Drain()
	if len(cov) != 2 {
		t.Fatalf("got %d records, want 2 — a flush spanning a boundary must not merge buckets", len(cov))
	}
	if !cov[0].Bucket.Before(cov[1].Bucket) {
		t.Error("records must come out oldest first")
	}
	if cov[0].ObservedPackets != 10 || cov[1].ObservedPackets != 20 {
		t.Errorf("packets landed in the wrong buckets: %d then %d", cov[0].ObservedPackets, cov[1].ObservedPackets)
	}
}

func TestDrainClears(t *testing.T) {
	h := NewCaptureHealth()
	h.Register("eth0")
	h.Up("eth0")
	h.Tick(time.Now(), Window{Elapsed: time.Second})
	if len(h.Drain()) != 1 {
		t.Fatal("expected one record")
	}
	if got := h.Drain(); got != nil {
		t.Errorf("second drain returned %d records, want none", len(got))
	}
}
