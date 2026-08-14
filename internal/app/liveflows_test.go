package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

type fakeSink struct {
	batches  [][]model.Flow
	coverage []model.Coverage
}

func (f *fakeSink) WriteFlows(flows []model.Flow) error {
	f.batches = append(f.batches, flows)
	return nil
}

func (f *fakeSink) WriteCoverage(cov []model.Coverage) error {
	f.coverage = append(f.coverage, cov...)
	return nil
}

type fakePublisher struct{ events []api.Event }

func (p *fakePublisher) Publish(e api.Event) { p.events = append(p.events, e) }

func mkFlow(src, dst string, end time.Time, bytes uint64) model.Flow {
	return model.Flow{
		Start:    end.Add(-time.Second),
		End:      end,
		SrcIP:    netip.MustParseAddr(src),
		DstIP:    netip.MustParseAddr(dst),
		Proto:    model.ProtoTCP,
		OutBytes: bytes,
	}
}

func TestLiveFlowsTeesPublishesAndBackfills(t *testing.T) {
	sink := &fakeSink{}
	pub := &fakePublisher{}
	lf := newLiveFlows(sink, pub, nil)

	base := time.Unix(1000, 0)
	if err := lf.WriteFlows([]model.Flow{
		mkFlow("192.168.1.2", "1.1.1.1", base, 100),
		mkFlow("192.168.1.3", "8.8.8.8", base.Add(2*time.Second), 200),
	}); err != nil {
		t.Fatal(err)
	}

	// Forwarded to the wrapped sink unchanged.
	if len(sink.batches) != 1 || len(sink.batches[0]) != 2 {
		t.Fatalf("wrapped sink got %v, want one batch of 2", sink.batches)
	}
	// Published exactly one "flows" event carrying the projection.
	if len(pub.events) != 1 || pub.events[0].Type != "flows" {
		t.Fatalf("published %v, want one flows event", pub.events)
	}
	if got, ok := pub.events[0].Data.([]api.LiveFlow); !ok || len(got) != 2 {
		t.Fatalf("event payload = %T len, want []api.LiveFlow of 2", pub.events[0].Data)
	}

	// Back-fill is newest-first by end time.
	recent := lf.RecentFlows()
	if len(recent) != 2 {
		t.Fatalf("RecentFlows len = %d, want 2", len(recent))
	}
	if recent[0].Src != "192.168.1.3" {
		t.Errorf("newest first: got %s, want 192.168.1.3", recent[0].Src)
	}
}

func TestLiveFlowsRingIsBounded(t *testing.T) {
	lf := newLiveFlows(&fakeSink{}, &fakePublisher{}, nil)
	base := time.Unix(0, 0)
	for i := 0; i < liveRingSize+50; i++ {
		_ = lf.WriteFlows([]model.Flow{mkFlow("10.0.0.1", "10.0.0.2", base.Add(time.Duration(i)*time.Second), 1)})
	}
	if got := len(lf.RecentFlows()); got != liveRingSize {
		t.Errorf("ring size = %d, want capped at %d", got, liveRingSize)
	}
}

func TestLiveFlowsEmptyBatchDoesNotPublish(t *testing.T) {
	pub := &fakePublisher{}
	lf := newLiveFlows(&fakeSink{}, pub, nil)
	if err := lf.WriteFlows(nil); err != nil {
		t.Fatal(err)
	}
	if len(pub.events) != 0 {
		t.Errorf("empty batch published %d events, want 0", len(pub.events))
	}
}

func TestLiveFlowsBlockedFlag(t *testing.T) {
	// Badge decision is flow-based: here, inbound-initiated flows only —
	// the shape used for country coverage.
	lf := newLiveFlows(&fakeSink{}, &fakePublisher{}, func(f model.Flow) bool {
		return f.Dir == model.DirWANtoLAN
	})
	in := mkFlow("9.9.9.9", "192.168.1.2", time.Unix(1000, 0), 100)
	in.Dir = model.DirWANtoLAN
	out := mkFlow("192.168.1.2", "9.9.9.9", time.Unix(1001, 0), 100)
	out.Dir = model.DirLANtoWAN
	if err := lf.WriteFlows([]model.Flow{in, out}); err != nil {
		t.Fatal(err)
	}
	for _, r := range lf.RecentFlows() {
		want := r.Dir == string(model.DirWANtoLAN)
		if r.Blocked != want {
			t.Errorf("flow dir %s: blocked = %v, want %v", r.Dir, r.Blocked, want)
		}
	}
}
