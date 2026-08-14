package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func mkFlow(t time.Time, src, dst string, dport uint16, bytes uint64) model.Flow {
	return model.Flow{
		Start: t, End: t.Add(2 * time.Second),
		SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		SrcPort: 40000, DstPort: dport, Proto: model.ProtoTCP, Dir: model.DirLANtoWAN,
		OutBytes: bytes, OutPackets: 10, InBytes: bytes / 2, InPackets: 8,
	}
}

func TestWriteFlowsAndRollups(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	// Two flows in the same minute from the same source to the same dst/port
	// must accumulate into one rollup row with flows=2.
	flows := []model.Flow{
		mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 1000),
		mkFlow(base.Add(10*time.Second), "192.168.1.10", "9.9.9.9", 443, 500),
		mkFlow(base.Add(20*time.Second), "192.168.1.11", "1.1.1.1", 53, 200),
	}
	if err := s.WriteFlows(flows); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	n, err := s.CountFlows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("raw flow count = %d, want 3", n)
	}

	// rollup_1m: expect two distinct tuples; the .10→9.9.9.9:443 tuple has
	// flows=2 and bytes = (1000+500)*1.5.
	var flowsCol, bytesCol int64
	err = s.db.QueryRow(`SELECT flows, bytes FROM rollup_1m
		WHERE src_ip='192.168.1.10' AND dst_ip='9.9.9.9' AND dst_port=443`).Scan(&flowsCol, &bytesCol)
	if err != nil {
		t.Fatalf("rollup query: %v", err)
	}
	if flowsCol != 2 {
		t.Errorf("accumulated flows = %d, want 2", flowsCol)
	}
	if want := int64(float64(1500) * 1.5); bytesCol != want {
		t.Errorf("accumulated bytes = %d, want %d", bytesCol, want)
	}
}

func TestThroughputSeries(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	// Flows across two separate minutes.
	_ = s.WriteFlows([]model.Flow{
		mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 1000),
		mkFlow(base.Add(90*time.Second), "192.168.1.10", "9.9.9.9", 443, 2000),
	})

	series, err := s.Throughput(ctx, base.Add(-time.Minute), base.Add(5*time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	// The series is dense: one point per minute across the whole range, not
	// one per minute that happened to carry traffic.
	if len(series.Points) != 6 {
		t.Fatalf("got %d points, want 6 (one per bucket in range)", len(series.Points))
	}
	if series.BucketSeconds != 60 {
		t.Errorf("bucket_seconds = %d, want 60", series.BucketSeconds)
	}
	var withBytes int
	for i, p := range series.Points {
		if i > 0 && !series.Points[i-1].Time.Before(p.Time) {
			t.Fatal("points not ordered by time ascending")
		}
		if p.Bytes != nil && *p.Bytes > 0 {
			withBytes++
		}
	}
	if withBytes != 2 {
		t.Errorf("%d buckets carry bytes, want 2", withBytes)
	}
}

func TestTopTalkers(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	_ = s.WriteFlows([]model.Flow{
		mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 5000),
		mkFlow(base, "192.168.1.11", "1.1.1.1", 443, 1000),
	})

	talkers, err := s.TopTalkers(ctx, base.Add(-time.Minute), base.Add(time.Minute), Res1m, 10)
	if err != nil {
		t.Fatalf("TopTalkers: %v", err)
	}
	if len(talkers) != 2 {
		t.Fatalf("got %d talkers, want 2", len(talkers))
	}
	if talkers[0].Address != "192.168.1.10" {
		t.Errorf("top talker = %s, want 192.168.1.10", talkers[0].Address)
	}
}

func TestChooseResolution(t *testing.T) {
	cases := []struct {
		span time.Duration
		want Resolution
	}{
		{time.Hour, Res1m},
		{24 * time.Hour, Res1h},
		{365 * 24 * time.Hour, Res1d},
	}
	for _, c := range cases {
		if got := ChooseResolution(c.span); got != c.want {
			t.Errorf("ChooseResolution(%v) = %s, want %s", c.span, got, c.want)
		}
	}
}
