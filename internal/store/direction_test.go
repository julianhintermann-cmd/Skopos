package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// dirFlow is a flow with its direction split stated outright, because these
// tests are about nothing else.
func dirFlow(at time.Time, src, dst string, dir model.Direction, out, in uint64) model.Flow {
	return model.Flow{
		Start: at, End: at.Add(2 * time.Second),
		SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		SrcPort: 40000, DstPort: 443, Proto: model.ProtoTCP, Dir: dir,
		OutBytes: out, OutPackets: 10, InBytes: in, InPackets: 8,
	}
}

// preMigrationRow writes a rollup row the way every row in the database looked
// before migration 0011: a byte total and no out_bytes at all.
func preMigrationRow(t *testing.T, s *Store, at time.Time, src, dst string, dir model.Direction, bytes int64) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO rollup_1m
		(bucket_ms, src_ip, dst_ip, dst_port, proto, direction, bytes, packets, flows)
		VALUES (?,?,?,?,?,?,?,?,1)`,
		toMs(bucket(at, bucket1m)), src, dst, 443, uint8(model.ProtoTCP), string(dir), bytes, 10); err != nil {
		t.Fatalf("seeding a pre-0011 rollup row: %v", err)
	}
}

// The one that decides whether any of this may ship. A bucket recorded before
// the direction column existed knows its total and nothing else. Reporting a
// split for it — any split, including 0 up — invents a fact about the
// operator's network that the raw flows can no longer contradict, because they
// were deleted after seven days and this row will be kept for two years.
func TestPreMigrationBucketReportsNoDirectionSplit(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	preMigrationRow(t, s, base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 4000)
	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}

	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatalf("Throughput: %v", err)
	}
	p := pointAt(t, series, base)

	if p.Bytes == nil || *p.Bytes != 4000 {
		t.Fatalf("bytes = %v, want the 4000 that were genuinely measured", p.Bytes)
	}
	if p.OutBytes != nil || p.InBytes != nil {
		t.Fatalf("a bucket from before migration 0011 reported a split it cannot know: out=%v in=%v",
			deref(p.OutBytes), deref(p.InBytes))
	}
	if series.Coverage.DirectionUnrecorded != 1 || series.Coverage.DirectionRecorded != 0 {
		t.Errorf("coverage said recorded=%d unrecorded=%d, want 0 and 1",
			series.Coverage.DirectionRecorded, series.Coverage.DirectionUnrecorded)
	}

	// And it must not reach the wire as a zero either. omitempty on a nil
	// pointer is the only thing standing between "not recorded" and a chart
	// drawing a zero-height upload band across last winter.
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "out_bytes") || strings.Contains(string(b), "in_bytes") {
		t.Errorf("an unrecorded split was serialised anyway: %s", b)
	}
}

// A bucket that was already on disk when 0012 ran and then took more traffic
// holds bytes from both sides of the migration. Adding today's split into it
// would produce an out_bytes covering part of the bucket and presented as
// covering all of it, so plain SQL addition keeps NULL winning.
func TestBucketStraddlingTheMigrationStaysUnrecorded(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	// Same tuple: the upsert's DO UPDATE path adds into the NULL.
	preMigrationRow(t, s, base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 4000)
	// Different tuple in the same bucket: the aggregate's guard catches it.
	preMigrationRow(t, s, base, "192.168.1.11", "9.9.9.9", model.DirLANtoWAN, 100)

	if err := s.WriteFlows([]model.Flow{
		dirFlow(base.Add(10*time.Second), "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 900, 100),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}

	var raw *int64
	if err := s.db.QueryRow(`SELECT out_bytes FROM rollup_1m
		WHERE src_ip='192.168.1.10' AND dst_ip='9.9.9.9'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		t.Errorf("out_bytes = %d on a row that was partly written before the column existed, want NULL", *raw)
	}

	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatal(err)
	}
	if p := pointAt(t, series, base); p.OutBytes != nil {
		t.Errorf("a bucket mixing pre- and post-0012 rows reported out=%d, want no split", *p.OutBytes)
	}
}

// The split the network-wide chart draws is about the boundary: what left for
// the internet and what arrived from it. Traffic between two local machines
// crossed nothing and belongs to neither side, so the two halves are allowed
// to sum to less than the total — and the shortfall is that local traffic, not
// a lost measurement.
func TestNetworkSplitCountsTheBoundaryOnly(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{
		dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 1000, 200),
		dirFlow(base, "8.8.8.8", "192.168.1.10", model.DirWANtoLAN, 5000, 50),
		dirFlow(base, "192.168.1.10", "192.168.1.11", model.DirLANtoLAN, 700, 300),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}

	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatal(err)
	}
	p := pointAt(t, series, base)
	if p.OutBytes == nil || p.InBytes == nil {
		t.Fatal("a bucket written entirely after 0012 has no split")
	}
	if *p.OutBytes != 1050 {
		t.Errorf("egress = %d, want 1050 (1000 sent out, plus the 50 replied to an inbound flow)", *p.OutBytes)
	}
	if *p.InBytes != 5200 {
		t.Errorf("ingress = %d, want 5200 (5000 arrived, plus 200 replied by the far end)", *p.InBytes)
	}
	if want := *p.Bytes - *p.OutBytes - *p.InBytes; want != 1000 {
		t.Errorf("bytes minus both halves = %d, want the 1000 bytes of purely local traffic", want)
	}
	if series.Coverage.DirectionRecorded != 1 || series.Coverage.DirectionSampled != 0 {
		t.Errorf("coverage said recorded=%d sampled=%d, want 1 and 0",
			series.Coverage.DirectionRecorded, series.Coverage.DirectionSampled)
	}
}

// A device series is about the device, and out_bytes on a rollup row is about
// the row's source. Where the device is the destination the two are opposites,
// and summing the column as stored would file every download the device made
// as an upload — precisely the reading ("is the camera uploading, or is
// someone hammering it") the split exists to answer.
func TestDeviceSplitIsFromTheDevicePerspective(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{
		dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 1000, 200),
		dirFlow(base, "8.8.8.8", "192.168.1.10", model.DirWANtoLAN, 5000, 50),
		dirFlow(base, "192.168.1.10", "192.168.1.11", model.DirLANtoLAN, 700, 300),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}

	series, err := s.DeviceThroughput(ctx, "192.168.1.10", base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatal(err)
	}
	p := pointAt(t, series, base)
	if p.OutBytes == nil || p.InBytes == nil {
		t.Fatal("the device series carries no split")
	}
	if *p.OutBytes != 1750 {
		t.Errorf("device sent = %d, want 1750 (1000 out + 50 replied + 700 local)", *p.OutBytes)
	}
	if *p.InBytes != 5500 {
		t.Errorf("device received = %d, want 5500 (200 + 5000 + 300)", *p.InBytes)
	}
	// Every byte here has the device on one end, so unlike the network-wide
	// series the halves account for the whole total.
	if *p.OutBytes+*p.InBytes != *p.Bytes {
		t.Errorf("%d + %d != %d: a device series must split its whole total",
			*p.OutBytes, *p.InBytes, *p.Bytes)
	}
}

// Under sampling both halves are floors of one undercount, so the ratio holds
// and the absolutes do not. The series says so itself rather than leaving a
// caller to rederive it from the state and the keep rate.
func TestSampledSplitIsCountedAsFloors(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{
		dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 900, 100),
	}); err != nil {
		t.Fatal(err)
	}
	cov := fullMinute(base)
	cov.ObservedPackets, cov.KeptPackets = 10000, 1000
	if err := s.WriteCoverage([]model.Coverage{cov}); err != nil {
		t.Fatal(err)
	}

	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatal(err)
	}
	p := pointAt(t, series, base)
	if p.State != StateSampled {
		t.Fatalf("state = %q, want %q", p.State, StateSampled)
	}
	if p.OutBytes == nil || *p.OutBytes != 900 {
		t.Errorf("egress = %v, want the unscaled floor 900", deref(p.OutBytes))
	}
	if series.Coverage.DirectionSampled != 1 {
		t.Errorf("direction_sampled = %d, want 1: the split is a ratio of floors and must say so",
			series.Coverage.DirectionSampled)
	}
}

// A quiet minute is not an unrecorded one. With the capture up and no rollup
// rows there is no row whose direction could be missing, so the split of zero
// bytes is zero and zero — otherwise every quiet night reads as a recording
// fault.
func TestQuietBucketSplitsZeroRatherThanNothing(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteCoverage([]model.Coverage{fullMinute(base)}); err != nil {
		t.Fatal(err)
	}
	series, err := s.Throughput(ctx, base, base.Add(time.Minute), Res1m)
	if err != nil {
		t.Fatal(err)
	}
	p := pointAt(t, series, base)
	if p.OutBytes == nil || *p.OutBytes != 0 || p.InBytes == nil || *p.InBytes != 0 {
		t.Errorf("a measured-zero bucket reported out=%v in=%v, want 0 and 0",
			deref(p.OutBytes), deref(p.InBytes))
	}
	if series.Coverage.DirectionUnrecorded != 0 {
		t.Errorf("direction_unrecorded = %d, want 0", series.Coverage.DirectionUnrecorded)
	}
}

// A talker's split is always read from that talker's own end of the flow, so
// the same field means the same thing whether the query grouped by source or
// by destination. Swapping them would show a host being scanned as the one
// doing the talking.
func TestTalkerSplitFollowsItsOwnAddress(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	if err := s.WriteFlows([]model.Flow{
		dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 1000, 200),
		dirFlow(base, "8.8.8.8", "192.168.1.10", model.DirWANtoLAN, 5000, 50),
	}); err != nil {
		t.Fatal(err)
	}

	talkers, err := s.TopTalkers(ctx, base, base.Add(time.Minute), Res1m, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Talker{}
	for _, tk := range talkers {
		got[tk.Address] = tk
	}
	if tk := got["8.8.8.8"]; tk.OutBytes == nil || *tk.OutBytes != 5000 || tk.InBytes == nil || *tk.InBytes != 50 {
		t.Errorf("8.8.8.8 sent/received = %v/%v, want 5000/50", deref(tk.OutBytes), deref(tk.InBytes))
	}
	if tk := got["192.168.1.10"]; tk.OutBytes == nil || *tk.OutBytes != 1000 || tk.InBytes == nil || *tk.InBytes != 200 {
		t.Errorf("192.168.1.10 sent/received = %v/%v, want 1000/200", deref(tk.OutBytes), deref(tk.InBytes))
	}

	// Grouped by destination instead, the same rule has to hold from the other
	// end: what the destination sent is what the device downloaded.
	dests, err := s.DeviceDestinations(ctx, "192.168.1.10", base, base.Add(time.Minute), Res1m, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dests) != 1 {
		t.Fatalf("got %d destinations, want 1", len(dests))
	}
	if dests[0].OutBytes == nil || *dests[0].OutBytes != 200 {
		t.Errorf("destination sent = %v, want the 200 it replied with", deref(dests[0].OutBytes))
	}
}

// A talker whose bytes come partly from before 0012 has no split, for the same
// reason a bucket does not: SUM skips NULLs, so an unguarded aggregate would
// report the post-migration rows' upload as the talker's whole upload.
func TestTalkerWithPreMigrationRowsHasNoSplit(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	preMigrationRow(t, s, base, "192.168.1.10", "1.1.1.1", model.DirLANtoWAN, 4000)
	if err := s.WriteFlows([]model.Flow{
		dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 1000, 200),
	}); err != nil {
		t.Fatal(err)
	}

	talkers, err := s.TopTalkers(ctx, base, base.Add(time.Minute), Res1m, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(talkers) != 1 {
		t.Fatalf("got %d talkers, want 1", len(talkers))
	}
	if talkers[0].OutBytes != nil {
		t.Errorf("talker reported sent = %d over rows that partly predate the column, want no split",
			*talkers[0].OutBytes)
	}
}

// The unnamed share is bounded by the raw flows, which retention deletes first
// when the hot cap is hit — so it answers over whatever survived, and says how
// long that was rather than letting the percentage read as all time.
func TestDeviceNamingReportsTheWindowItCouldAnswerOver(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	named := dirFlow(base, "192.168.1.10", "9.9.9.9", model.DirLANtoWAN, 1000, 0)
	named.DstName = "updates.example"
	if err := s.WriteFlows([]model.Flow{
		named,
		dirFlow(base, "192.168.1.10", "203.0.113.7", model.DirLANtoWAN, 3000, 0),
		// Local traffic is excluded: its names come from mDNS, not from
		// anything the device asked a resolver for.
		dirFlow(base, "192.168.1.10", "192.168.1.11", model.DirLANtoLAN, 9999, 0),
	}); err != nil {
		t.Fatal(err)
	}

	from := base.Add(-24 * time.Hour)
	to := base.Add(time.Minute)
	n, err := s.DeviceNaming(ctx, "192.168.1.10", from, to)
	if err != nil {
		t.Fatalf("DeviceNaming: %v", err)
	}
	if n.NamedBytes != 1000 || n.UnnamedBytes != 3000 {
		t.Errorf("named/unnamed = %d/%d, want 1000/3000", n.NamedBytes, n.UnnamedBytes)
	}
	if !n.Truncated {
		t.Error("asked about 24 hours of a database whose oldest flow is minutes old, and it did not say so")
	}
	if !n.WindowFrom.Equal(base) {
		t.Errorf("window_from = %s, want the oldest surviving flow at %s", n.WindowFrom, base)
	}
	if n.WindowDays <= 0 || n.WindowDays > 1 {
		t.Errorf("window_days = %v, want a fraction of one day", n.WindowDays)
	}
}

func deref(p *int64) any {
	if p == nil {
		return "not recorded"
	}
	return *p
}
