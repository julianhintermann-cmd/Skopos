package store

import (
	"context"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// fullMinute is a coverage record for one wholly covered minute with one live
// source and no sampling — the ordinary case.
func fullMinute(at time.Time) model.Coverage {
	return model.Coverage{
		Bucket: at, SourcesTotal: 1, SourcesUp: 1, SecondsCovered: 60,
	}
}

func pointAt(t *testing.T, s Series, at time.Time) Point {
	t.Helper()
	for _, p := range s.Points {
		if p.Time.Equal(at.UTC().Truncate(time.Minute)) {
			return p
		}
	}
	t.Fatalf("no point for %s in a series of %d points — the series is not dense", at, len(s.Points))
	return Point{}
}

// A bucket recorded while the capture was sampling must carry the keep rate
// its byte count is a fraction of. Without it the stored value is a tenth of
// the truth shown as a total, and the flood that caused the sampling renders
// as a dip.
func TestSampledBucketCarriesItsKeepRate(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 1000)}); err != nil {
		t.Fatal(err)
	}
	// 10 000 packets crossed the wire; 1 000 survived the sampler.
	cov := fullMinute(base)
	cov.ObservedPackets, cov.KeptPackets = 10000, 1000
	if err := s.WriteCoverage([]model.Coverage{cov}); err != nil {
		t.Fatalf("WriteCoverage: %v", err)
	}

	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	p := pointAt(t, series, base)
	if p.State != StateSampled {
		t.Fatalf("state = %q, want %q", p.State, StateSampled)
	}
	if p.KeepRate == nil {
		t.Fatal("a sampled bucket was stored without its keep rate: the byte count is unqualified")
	}
	if *p.KeepRate < 0.09 || *p.KeepRate > 0.11 {
		t.Errorf("keep rate = %v, want ~0.1 (1000 kept of 10000 observed)", *p.KeepRate)
	}
	// The stored value stays the measured floor. Scaling it here would replace
	// the only thing observed with an inference nothing downstream could tell
	// from a measurement.
	if p.Bytes == nil || *p.Bytes != 1500 {
		t.Errorf("bytes = %v, want the unscaled measured floor 1500", p.Bytes)
	}
	// The bucket's packet total, unlike its bytes, is exact under sampling.
	if p.ObservedPackets == nil || *p.ObservedPackets != 10000 {
		t.Errorf("observed_packets = %v, want the exact pre-sampling total 10000", p.ObservedPackets)
	}
}

// A bucket that has not finished yet is not a bucket with a coverage deficit.
// Flagging it would put a permanent warning on the newest point of every chart.
func TestStillOpenBucketIsNotFlaggedPartial(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	// Twelve seconds into the minute, twelve heartbeats recorded.
	cov := model.Coverage{Bucket: base, SourcesTotal: 1, SourcesUp: 1, SecondsCovered: 12}
	if err := s.WriteCoverage([]model.Coverage{cov}); err != nil {
		t.Fatal(err)
	}
	now := base.Add(12 * time.Second)
	if p := pointAt(t, mustSeries(t, s, ctx, base, now), base); p.State != StateMeasured {
		t.Errorf("open bucket = %q, want %q", p.State, StateMeasured)
	}
	// Once the minute has closed, twelve of sixty seconds really is partial.
	closed := mustSeries(t, s, ctx, base, base.Add(2*time.Minute))
	if p := pointAt(t, closed, base); p.State != StateSampled {
		t.Errorf("closed bucket with 12/60 seconds = %q, want %q", p.State, StateSampled)
	}
}

// A minute with the capture up and no traffic is a measurement of zero and
// must plot at zero. A minute with no capture is an absence and must be a gap.
// Before the coverage track both wrote nothing at all, so the two were
// byte-identical in the database.
func TestQuietMinuteIsNotACaptureGap(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	quiet := base
	dead := base.Add(time.Minute)
	down := fullMinute(dead)
	down.SourcesUp = 0
	if err := s.WriteCoverage([]model.Coverage{fullMinute(quiet), down}); err != nil {
		t.Fatalf("WriteCoverage: %v", err)
	}

	series, err := s.Throughput(ctx, quiet, dead.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	q, d := pointAt(t, series, quiet), pointAt(t, series, dead)

	if q.State == d.State {
		t.Fatalf("a quiet minute and a dead capture both read as %q — they are indistinguishable", q.State)
	}
	if q.State != StateMeasured {
		t.Errorf("quiet minute state = %q, want %q", q.State, StateMeasured)
	}
	if q.Bytes == nil || *q.Bytes != 0 {
		t.Errorf("quiet minute bytes = %v, want a plotted zero", q.Bytes)
	}
	if d.State != StateDown {
		t.Errorf("dead capture state = %q, want %q", d.State, StateDown)
	}
	if d.Bytes != nil || d.Packets != nil || d.Flows != nil {
		t.Errorf("dead capture must carry nulls, got bytes=%v packets=%v flows=%v", d.Bytes, d.Packets, d.Flows)
	}
	if series.Coverage.Measured != 1 || series.Coverage.Down != 1 {
		t.Errorf("coverage histogram = %+v, want 1 measured and 1 down", series.Coverage)
	}
}

// Buckets older than the first coverage record are outside recorded history.
// Back-filling them as complete would promote an assumption to a measurement.
func TestHistoryBeforeCoverageReadsAsNoData(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	old := base.Add(-10 * time.Minute)
	if err := s.WriteFlows([]model.Flow{mkFlow(old, "192.168.1.10", "9.9.9.9", 443, 1000)}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}

	series, err := s.Throughput(ctx, old, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	if p := pointAt(t, series, old); p.State != StateNoData || p.Bytes != nil {
		t.Errorf("pre-coverage bucket = %q with bytes %v, want %q and a gap", p.State, p.Bytes, StateNoData)
	}
	if p := pointAt(t, series, base); p.State != StateMeasured {
		t.Errorf("covered bucket = %q, want %q", p.State, StateMeasured)
	}
}

// With no coverage recorded at all — a database from before this release —
// what the rollups hold is still a measurement, and what they do not hold is
// still an absence. Neither becomes a zero.
func TestWithoutAnyCoverageRollupsStillReadAsMeasured(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 1000)}); err != nil {
		t.Fatal(err)
	}
	series, err := s.Throughput(ctx, base, base.Add(2*time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	if p := pointAt(t, series, base); p.State != StateMeasured || p.Bytes == nil {
		t.Errorf("bucket with traffic = %q bytes %v, want %q with a value", p.State, p.Bytes, StateMeasured)
	}
	if p := pointAt(t, series, base.Add(time.Minute)); p.State != StateNoData || p.Bytes != nil {
		t.Errorf("bucket without traffic = %q bytes %v, want %q and a gap", p.State, p.Bytes, StateNoData)
	}
}

// A capture that lost one of two interfaces saw half the network. That is a
// coverage deficit a keep rate cannot express, so the sources ride along.
func TestPartialSourceCoverageIsReported(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	cov := fullMinute(base)
	cov.SourcesTotal, cov.SourcesUp = 2, 1
	if err := s.WriteCoverage([]model.Coverage{cov}); err != nil {
		t.Fatal(err)
	}
	p := pointAt(t, mustSeries(t, s, ctx, base, base.Add(time.Minute)), base)
	if p.State != StateSampled {
		t.Fatalf("state = %q, want %q", p.State, StateSampled)
	}
	if p.SourcesUp == nil || p.SourcesTotal == nil || *p.SourcesUp != 1 || *p.SourcesTotal != 2 {
		t.Errorf("sources = %v of %v, want 1 of 2", p.SourcesUp, p.SourcesTotal)
	}
}

// A bucket is assembled from however many flushes land inside it: packet
// counts and covered seconds add up, and sources_up takes the minimum because
// "up for part of the bucket" is not up for the bucket.
func TestCoverageAccumulatesWithinABucket(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	first := model.Coverage{Bucket: base, SourcesTotal: 2, SourcesUp: 2, SecondsCovered: 30, ObservedPackets: 100, KeptPackets: 100}
	second := model.Coverage{Bucket: base.Add(30 * time.Second), SourcesTotal: 2, SourcesUp: 1, SecondsCovered: 30, ObservedPackets: 300, KeptPackets: 100}
	if err := s.WriteCoverage([]model.Coverage{first}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCoverage([]model.Coverage{second}); err != nil {
		t.Fatal(err)
	}

	var total, up, observed, kept, seconds int64
	err := s.db.QueryRow(`SELECT sources_total, sources_up, observed_packets, kept_packets, seconds_covered
		FROM coverage_1m WHERE bucket_ms = ?`, toMs(base)).
		Scan(&total, &up, &observed, &kept, &seconds)
	if err != nil {
		t.Fatalf("coverage_1m: %v", err)
	}
	if total != 2 || up != 1 {
		t.Errorf("sources = %d of %d, want 1 of 2 (minimum across the bucket)", up, total)
	}
	if observed != 400 || kept != 200 {
		t.Errorf("packets observed=%d kept=%d, want 400/200", observed, kept)
	}
	if seconds != 60 {
		t.Errorf("seconds_covered = %d, want 60", seconds)
	}

	// The same records fan out to the coarser resolutions.
	p := pointAt(t, mustSeries(t, s, ctx, base, base.Add(time.Minute)), base)
	if p.State != StateSampled || p.KeepRate == nil || *p.KeepRate != 0.5 {
		t.Errorf("state=%q keep_rate=%v, want sampled at 0.5", p.State, p.KeepRate)
	}
}

// The series must be dense even where nothing was recorded: an omitted bucket
// is one uPlot draws a straight line across.
func TestThroughputIsDenseAcrossAGap(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{
		mkFlow(base, "192.168.1.10", "9.9.9.9", 443, 1000),
		mkFlow(base.Add(3*time.Minute), "192.168.1.10", "9.9.9.9", 443, 2000),
	}); err != nil {
		t.Fatal(err)
	}
	series := mustSeries(t, s, ctx, base, base.Add(4*time.Minute))
	if len(series.Points) != 4 {
		t.Fatalf("got %d points, want 4 — one per bucket, gaps included", len(series.Points))
	}
	for _, i := range []int{1, 2} {
		if series.Points[i].Bytes != nil {
			t.Errorf("point %d has bytes %v, want a null the chart can break on", i, *series.Points[i].Bytes)
		}
	}
}

func TestThroughputRefusesAnAbsurdlyLongSeries(t *testing.T) {
	s, base := testStore(t)
	if _, err := s.Throughput(context.Background(), base, base.Add(maxSeriesPoints*2*24*time.Hour), Res1d); err == nil {
		t.Error("a series past the point limit must error, not silently truncate")
	}
}

func mustSeries(t *testing.T, s *Store, ctx context.Context, from, to time.Time) Series {
	t.Helper()
	series, err := s.Throughput(ctx, from, to, Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	return series
}
