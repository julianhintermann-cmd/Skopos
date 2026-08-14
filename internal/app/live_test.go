package app

import (
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

func meterAt(now *time.Time, samp func() flow.SampleState) *liveMeter {
	return newLiveMeter(func() time.Time { return *now }, samp)
}

// A capture that has stopped and a network that has gone quiet both produce
// bytes == lastBytes, so both used to be reported as exactly 0 bit/s in the
// accent colour. There is no measurement in the first case and the payload
// must say so by omitting the field.
func TestSnapshotOmitsRatesWhenCaptureIsDown(t *testing.T) {
	now := time.Unix(1000, 0)
	state := flow.SampleState{Capture: flow.CaptureUp, SourcesUp: 1, SourcesTotal: 1, KeepRate: 1}
	m := meterAt(&now, func() flow.SampleState { return state })

	// Capture up, no traffic: zero is a measurement and is reported.
	now = now.Add(time.Second)
	quiet := m.Snapshot()
	if quiet.BitsPerSecond == nil || *quiet.BitsPerSecond != 0 {
		t.Fatalf("quiet network: bits_per_second = %v, want a measured 0", quiet.BitsPerSecond)
	}
	if quiet.Capture != "up" {
		t.Errorf("capture = %q, want up", quiet.Capture)
	}

	// Capture down: identical counters, but there is nothing to report.
	state = flow.SampleState{Capture: flow.CaptureDown, SourcesUp: 0, SourcesTotal: 1}
	now = now.Add(time.Second)
	dead := m.Snapshot()
	if dead.BitsPerSecond != nil || dead.PacketsPerSecond != nil {
		t.Fatalf("dead capture reported %v bit/s: a quiet network and a dead capture are still identical",
			*dead.BitsPerSecond)
	}
	if dead.Capture != "down" {
		t.Errorf("capture = %q, want down", dead.Capture)
	}
	if dead.SourcesUp == nil || *dead.SourcesUp != 0 || dead.SourcesTotal == nil || *dead.SourcesTotal != 1 {
		t.Errorf("sources = %v of %v, want 0 of 1", dead.SourcesUp, dead.SourcesTotal)
	}
}

// last_packet_at is when a packet arrived, not when Snapshot was called. The
// meter held the second and reported neither.
func TestSnapshotReportsLastPacketAt(t *testing.T) {
	now := time.Unix(1000, 0)
	m := meterAt(&now, captureUp)

	if st := m.Snapshot(); st.LastPacketAt != nil {
		t.Errorf("no packet has arrived; last_packet_at = %v, want absent", st.LastPacketAt)
	}

	arrival := now.Add(500 * time.Millisecond)
	m.Observe(flow.Packet{Size: 100, Time: arrival})
	now = now.Add(2 * time.Second)

	st := m.Snapshot()
	if st.LastPacketAt == nil {
		t.Fatal("a packet arrived and last_packet_at is still absent")
	}
	if !st.LastPacketAt.Equal(arrival) {
		t.Errorf("last_packet_at = %v, want the packet's own time %v", st.LastPacketAt, arrival)
	}
	if st.MeasuredAt == nil || !st.MeasuredAt.Equal(now) {
		t.Errorf("measured_at = %v, want %v", st.MeasuredAt, now)
	}
}

// Under sampling the meter counts only the packets that survived, so its rate
// is a floor. The keep rate has to ship with it or the number is unqualified.
func TestSnapshotShipsTheKeepRateWithASampledRate(t *testing.T) {
	now := time.Unix(1000, 0)
	m := meterAt(&now, func() flow.SampleState {
		return flow.SampleState{
			Sampling: true, ObservedPPS: 90000, KeepRate: 0.1,
			Capture: flow.CaptureUp, SourcesUp: 1, SourcesTotal: 1,
		}
	})
	m.Observe(flow.Packet{Size: 1000, Time: now})
	now = now.Add(time.Second)

	st := m.Snapshot()
	if st.KeepRate == nil || *st.KeepRate != 0.1 {
		t.Fatalf("keep_rate = %v, want 0.1 alongside the floor", st.KeepRate)
	}
	if !st.Sampling {
		t.Error("sampling flag not reported")
	}
	if st.ObservedPPS == nil || *st.ObservedPPS != 90000 {
		t.Errorf("observed_pps = %v, want 90000 (exact, pre-sampling)", st.ObservedPPS)
	}
	// The floor itself is never scaled here.
	if st.BitsPerSecond == nil || *st.BitsPerSecond != 8000 {
		t.Errorf("bits_per_second = %v, want the unscaled floor 8000", st.BitsPerSecond)
	}
}

// Before any source reports, the state is "starting" rather than "down": every
// restart would otherwise look like a capture failure.
func TestSnapshotReportsStartingBeforeAnySourceReports(t *testing.T) {
	now := time.Unix(1000, 0)
	sampler := flow.NewSampler(0, nil)
	sampler.Health().Register("eth0")
	m := meterAt(&now, sampler.State)

	now = now.Add(time.Second)
	st := m.Snapshot()
	if st.Capture != "starting" {
		t.Errorf("capture = %q, want starting", st.Capture)
	}
	if st.BitsPerSecond != nil {
		t.Errorf("nothing is capturing yet; bits_per_second = %v, want absent", *st.BitsPerSecond)
	}
}
