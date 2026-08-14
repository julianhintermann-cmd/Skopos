package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Resolution selects which rollup table a time-series query reads from.
type Resolution string

const (
	Res1m Resolution = "1m"
	Res1h Resolution = "1h"
	Res1d Resolution = "1d"
)

func (r Resolution) table() (string, time.Duration, error) {
	switch r {
	case Res1m:
		return "rollup_1m", bucket1m, nil
	case Res1h:
		return "rollup_1h", bucket1h, nil
	case Res1d:
		return "rollup_1d", bucket1d, nil
	default:
		return "", 0, fmt.Errorf("unknown resolution %q", r)
	}
}

// ChooseResolution picks the coarsest rollup that still yields a reasonable
// number of points (≈ up to 720) across the requested span, so the dashboard
// asks for 1-minute data on a 1-hour view and daily data on a yearly one.
func ChooseResolution(span time.Duration) Resolution {
	switch {
	case span <= 12*time.Hour:
		return Res1m
	case span <= 90*24*time.Hour:
		return Res1h
	default:
		return Res1d
	}
}

// coarseness orders the resolutions so a requested one can be compared with
// the one the span actually warrants.
func (r Resolution) coarseness() int {
	switch r {
	case Res1h:
		return 1
	case Res1d:
		return 2
	default:
		return 0
	}
}

// ClampResolution honours a caller's requested resolution but never lets it be
// finer than the span warrants.
//
// Without this, one query parameter turned a 0.3 ms request into a 45 second
// one: asking for minute buckets over ninety days makes SQLite spill twenty-
// three million rows through two temporary B-trees. Every query in this
// process shares a single database connection, so that request also blocks the
// flow writer and every other page for its whole duration — and with
// authentication off and the port forwarded, anyone can send it, repeatedly.
// A coarser resolution than the span warrants is harmless and stays allowed.
func ClampResolution(requested Resolution, span time.Duration) Resolution {
	auto := ChooseResolution(span)
	switch requested {
	case Res1m, Res1h, Res1d:
		if requested.coarseness() < auto.coarseness() {
			return auto
		}
		return requested
	default:
		// Anything we do not recognise falls back to the span's own answer
		// rather than travelling on to fail deeper in as an unknown table.
		return auto
	}
}

// TimePoint is one bucket of a throughput series.
type TimePoint struct {
	Time    time.Time `json:"time"`
	Bytes   int64     `json:"bytes"`
	Packets int64     `json:"packets"`
	Flows   int64     `json:"flows"`
	// OutBytes and InBytes are nil when any rollup row folded into this bucket
	// predates migration 0011 and so recorded no direction.
	OutBytes *int64 `json:"out_bytes,omitempty"`
	InBytes  *int64 `json:"in_bytes,omitempty"`
}

// directionSum wraps a direction aggregate in the guard that keeps a partial
// answer from passing as a whole one.
//
// SUM ignores NULLs, so a bare SUM(out_bytes) over a group that mixes rows
// written before migration 0011 with rows written since reports the new rows'
// upload as though it were the group's entire upload: a real number, in the
// right units, wrong about what it covers, and impossible to spot downstream.
// COUNT counts only non-NULL values, so COUNT(out_bytes) = COUNT(*) is the
// cheap test for "every row here knows its direction", and the CASE yields SQL
// NULL — "not recorded" — when one does not.
func directionSum(expr string) string {
	return "CASE WHEN COUNT(out_bytes) = COUNT(*) THEN SUM(" + expr + ") END"
}

// The boundary-crossing halves of a rollup row, for the network-wide series.
//
// out_bytes is always source→destination, so which half of a row is leaving
// the network depends on which side of the boundary its source sits — that is
// what the direction column records. Traffic that never crossed the boundary,
// internal to internal and external to external, belongs to neither half; it
// stays in bytes and is left out of both. Assigning it a side would be the
// same invention as filling in a missing split.
const (
	egressExpr  = `CASE direction WHEN 'lan_wan' THEN out_bytes WHEN 'wan_lan' THEN bytes - out_bytes ELSE 0 END`
	ingressExpr = `CASE direction WHEN 'lan_wan' THEN bytes - out_bytes WHEN 'wan_lan' THEN out_bytes ELSE 0 END`
)

// The halves of a rollup row as one address sees them, for a query that
// matches rows at either end of the flow. Each takes that address as a bound
// parameter, ahead of the WHERE clause's own: which half the address sent
// turns on whether it is the row's source, and summing the column as stored
// would credit a device's downloads to its uploads — the exact number this
// change exists to get right.
const (
	subjectSentExpr = `CASE WHEN src_ip = ? THEN out_bytes ELSE bytes - out_bytes END`
	subjectRecvExpr = `CASE WHEN src_ip = ? THEN bytes - out_bytes ELSE out_bytes END`
)

// PointState says what a bucket's numbers mean. It is the discriminator that
// makes a chart honest: only down and nodata carry nulls, and only they may be
// drawn as a gap. A genuine zero is a measurement and plots at zero.
type PointState string

const (
	// StateMeasured is capture up, nothing sampled: the numbers are exact.
	StateMeasured PointState = "measured"
	// StateSampled is a coverage deficit — a keep rate below 1, an interface
	// missing, or a bucket only partly covered. The byte counts are a floor,
	// and KeepRate says what fraction of the packets they came from.
	StateSampled PointState = "sampled"
	// StateDown is capture not running. No measurement exists for the bucket.
	StateDown PointState = "down"
	// StateNoData is outside recorded history: before Skopos recorded
	// coverage, or pruned by retention.
	StateNoData PointState = "nodata"
	// StateUnverified is a bucket recorded before this release, which stored
	// throughput without recording whether the capture was complete.
	//
	// The numbers are present because they were measured — a rollup row exists
	// only because flows were flushed into it — but nothing says whether
	// sampling was active or an interface was down, and before 0.4.0 sampling
	// undercounted silently. So the bytes are a floor of unknown tightness:
	// more than nodata, which claims nothing, and less than measured, which
	// claims exactness.
	//
	// Drawing these as a gap would have been the tidier rule and it was wrong.
	// Refusing to show a number that was genuinely observed, because a second
	// fact about it is missing, discards evidence and reads to an operator as
	// data loss on upgrade.
	StateUnverified PointState = "unverified"
)

// Point is one bucket of a dense series.
type Point struct {
	Time  time.Time  `json:"time"`
	State PointState `json:"state"`
	// Bytes, Packets and Flows are nil exactly when State is down or nodata —
	// unverified carries real numbers whose completeness is unknown.
	// Under sampling they are what was measured — a floor — and are never
	// scaled by 1/keep_rate here: scaling would replace the one thing that was
	// observed with an inference indistinguishable from a measurement. The
	// estimate is floor/keep_rate and belongs to the render layer, labelled.
	Bytes   *int64 `json:"bytes"`
	Packets *int64 `json:"packets"`
	Flows   *int64 `json:"flows"`
	// KeepRate is the realized fraction of packets that survived sampling,
	// present only when State is sampled.
	KeepRate *float64 `json:"keep_rate,omitempty"`
	// ObservedPackets is the bucket's true packet total, exact even under
	// sampling: the sampler counts every packet before deciding whether to
	// drop it. Present only when State is sampled, where it is the honest
	// answer that Packets is not.
	//
	// The asymmetry is deliberate and surprising, so: this bucket total is
	// exact, while per-tuple packet counts — top talkers, ports, destinations
	// — remain sampled floors, because the exact count exists only in
	// aggregate and was never attributed to a source or destination.
	ObservedPackets *int64 `json:"observed_packets,omitempty"`
	// SourcesUp and SourcesTotal are present only when some but not all
	// capture sources covered the bucket — a coverage deficit KeepRate cannot
	// express, and the one the "1 of 2 interfaces" label needs.
	SourcesUp    *int `json:"sources_up,omitempty"`
	SourcesTotal *int `json:"sources_total,omitempty"`
	// OutBytes and InBytes split Bytes by which way it travelled, seen from
	// whatever the series is about: the device on a device series, the internal
	// network on the network-wide one.
	//
	// They are nil together, and nil means the split was not recorded — never
	// that it was zero. Every rollup row written before migration 0011 stored a
	// total and nothing else, so a bucket holding one of those cannot be told
	// apart from a bucket that really was all inbound. Drawing nil as a
	// zero-height band would manufacture exactly the distinction the column was
	// added to preserve, and the claim would outlive the raw flows that could
	// disprove it by 83 weeks.
	//
	// On the network-wide series the two can sum to less than Bytes. Traffic
	// that never crossed the boundary — internal to internal, external to
	// external — is counted in the total and belongs to neither side; the
	// remainder, Bytes - OutBytes - InBytes, is that local and transit traffic
	// and not a rounding error. On a device series every byte has the device on
	// one end, so the two always sum to Bytes.
	//
	// Under sampling both halves are floors of the same undercount: KeepRate
	// applies to the whole bucket, so the ratio between them survives and the
	// absolute numbers do not. CoverageCounts.DirectionSampled counts the
	// buckets where that caveat is live.
	OutBytes *int64 `json:"out_bytes,omitempty"`
	InBytes  *int64 `json:"in_bytes,omitempty"`
}

// CoverageCounts summarises a series so a caller can say "27 of 877 minutes
// not captured" without walking it. A dense array of nodata has a length, so
// len(series) > 0 is no longer a usable proxy for "there is data" — measured
// plus sampled is.
type CoverageCounts struct {
	Measured int `json:"measured"`
	Sampled  int `json:"sampled"`
	Down     int `json:"down"`
	NoData   int `json:"nodata"`
	// Unverified is history from before coverage was recorded: numbers exist,
	// their completeness does not. It shrinks to zero as that history ages out.
	Unverified int `json:"unverified"`
	// DirectionRecorded and DirectionUnrecorded split the buckets that carry
	// numbers by whether those numbers also carry an upload/download split.
	// Unrecorded is history from before migration 0011 and shrinks to zero as
	// that history ages out of the rollup; it is the count behind "direction
	// not recorded before <date>", which a chart has to say in words because
	// the missing band cannot say it for itself.
	DirectionRecorded   int `json:"direction_recorded"`
	DirectionUnrecorded int `json:"direction_unrecorded"`
	// DirectionSampled is how many of the recorded ones came out of a sampled
	// bucket, where the two halves are floors of one undercount: their ratio is
	// honest and their absolute values are not. Stated here rather than left
	// for the client to rederive from state and keep_rate, because a caller
	// that forgets presents floors as totals.
	DirectionSampled int `json:"direction_sampled"`
}

// Series is a dense throughput series: exactly one point per bucket in the
// requested range, in order, with no holes.
type Series struct {
	Resolution    Resolution     `json:"resolution"`
	BucketSeconds int            `json:"bucket_seconds"`
	Points        []Point        `json:"series"`
	Coverage      CoverageCounts `json:"coverage"`
}

// maxSeriesPoints bounds one series. A dense series is proportional to the
// span rather than to the data, so this is the backstop ClampResolution cannot
// provide: it leaves room for well over a century of daily buckets — any
// honest "show me everything" — and refuses the rest rather than truncating,
// because a truncated series that does not say so is the defect this file
// exists to fix.
const maxSeriesPoints = 50000

// Throughput returns total bytes/packets/flows per bucket between from and to
// (inclusive of from, exclusive of to) at the given resolution.
//
// The series is dense: one point per bucket, always. The previous contract
// omitted empty buckets and asked the caller to fill the gaps, and no caller
// ever did — so uPlot joined the last reading before an outage to the first
// one after it and drew a straight invented line across the exact period the
// operator most needs to see. Delegating an invariant to every present and
// future caller, with no way to fail loudly, is what failed; the honest answer
// is now the only representable one.
func (s *Store) Throughput(ctx context.Context, from, to time.Time, res Resolution) (Series, error) {
	table, size, err := res.table()
	if err != nil {
		return Series{}, err
	}
	// Align to bucket boundaries so the generated sequence lands on the same
	// grid the rollups are keyed by.
	start := bucket(from, size)
	end := bucket(to.Add(size-time.Nanosecond), size)
	if !end.After(start) {
		return Series{Resolution: res, BucketSeconds: int(size / time.Second), Points: []Point{}}, nil
	}
	n := int(end.Sub(start) / size)
	if n > maxSeriesPoints {
		return Series{}, fmt.Errorf("store: %s buckets over that range would be %d points, more than the %d limit",
			res, n, maxSeriesPoints)
	}

	totals, err := s.bucketTotals(ctx, table, start, end)
	if err != nil {
		return Series{}, err
	}
	return s.densify(ctx, totals, start, end, to, size, res, n)
}

// densify turns a sparse bucket→totals map into one point per bucket, each
// carrying what its numbers mean.
//
// It is shared rather than copied because a second implementation is a second
// chance to reintroduce the defect: the device chart used to return only the
// buckets that had traffic, and uPlot joined what was left with a straight
// line — a capture outage drawn as a smooth afternoon. Coverage is a fact
// about the capture, not about one device, so the same records answer for
// every series.
func (s *Store) densify(ctx context.Context, totals map[int64]TimePoint,
	start, end, to time.Time, size time.Duration, res Resolution, n int) (Series, error) {

	cov, horizon, recorded, err := s.coverage(ctx, start, end, res)
	if err != nil {
		return Series{}, err
	}

	out := Series{Resolution: res, BucketSeconds: int(size / time.Second), Points: make([]Point, 0, n)}
	for t := start; t.Before(end); t = t.Add(size) {
		// The last bucket of a live window has not finished yet. Judging it
		// incomplete would put a coverage warning on the newest point of every
		// chart, permanently — and a mark that is always on is a mark the
		// operator learns to ignore.
		open := t.Add(size).After(to)
		p := classify(t, toMs(t), totals, cov, horizon, recorded, out.BucketSeconds, open)
		switch p.State {
		case StateMeasured:
			out.Coverage.Measured++
		case StateSampled:
			out.Coverage.Sampled++
		case StateDown:
			out.Coverage.Down++
		case StateNoData:
			out.Coverage.NoData++
		case StateUnverified:
			out.Coverage.Unverified++
		}
		// Direction is a second, independent fact about a bucket: measured
		// history from before migration 0011 has exact byte totals and no split
		// at all, so it cannot ride on PointState.
		switch {
		case p.OutBytes != nil:
			out.Coverage.DirectionRecorded++
			if p.State == StateSampled {
				out.Coverage.DirectionSampled++
			}
		case p.Bytes != nil:
			out.Coverage.DirectionUnrecorded++
		}
		out.Points = append(out.Points, p)
	}
	return out, nil
}

// classify decides what one bucket's numbers mean from the rollup row and the
// coverage record, if either exists.
func classify(t time.Time, ms int64, totals map[int64]TimePoint, cov map[int64]coverageRow,
	horizon int64, recorded bool, bucketSeconds int, open bool) Point {

	p := Point{Time: t, State: StateNoData}
	total, measured := totals[ms]

	if !recorded {
		// Coverage has never been written — a database from before this
		// release, or a build whose heartbeat has not run. What was measured
		// is still a measurement; what was not is an absence, not a zero.
		if !measured {
			return p
		}
		p.State = StateMeasured
		p.Bytes, p.Packets, p.Flows = &total.Bytes, &total.Packets, &total.Flows
		p.OutBytes, p.InBytes = total.OutBytes, total.InBytes
		return p
	}
	if ms < horizon {
		// Older than the first coverage record. Whether the capture was
		// complete is unknown, and assuming it was would promote history to
		// verified on the strength of nothing.
		//
		// But a rollup row is itself evidence: it exists only because flows
		// were flushed into it, so those bytes were observed. Dropping them
		// for want of a second fact would discard a real measurement and blank
		// every chart the moment an operator upgrades — data loss in
		// appearance, and an untruth in its own right. Unverified says both
		// halves: here is what was seen, nobody recorded how much was missed.
		if measured {
			p.State = StateUnverified
			p.Bytes, p.Packets, p.Flows = &total.Bytes, &total.Packets, &total.Flows
			p.OutBytes, p.InBytes = total.OutBytes, total.InBytes
		}
		return p
	}
	c, ok := cov[ms]
	if !ok {
		return p // a heartbeat gap inside recorded history is still an absence
	}
	if c.sourcesUp == 0 {
		p.State = StateDown
		return p
	}

	// The capture was up. Absent rollup rows are therefore a measured zero,
	// not an absence — the one state the schema could not express before, and
	// the reason a quiet 3am and a dead capture used to look identical.
	vals := total
	p.Bytes, p.Packets, p.Flows = &vals.Bytes, &vals.Packets, &vals.Flows
	p.OutBytes, p.InBytes = vals.OutBytes, vals.InBytes
	if !measured {
		// A bucket with no rollup rows at all has no row whose direction could
		// be missing: zero bytes split as zero and zero. Leaving it nil would
		// punch "direction not recorded" holes through every quiet night, which
		// reads as a defect in the recording rather than as a quiet night.
		zeroOut, zeroIn := int64(0), int64(0)
		p.OutBytes, p.InBytes = &zeroOut, &zeroIn
	}

	rate := c.keepRate()
	partial := c.sourcesUp < c.sourcesTotal || (!open && c.secondsCovered < bucketSeconds)
	if rate >= 1 && !partial {
		p.State = StateMeasured
		return p
	}
	p.State = StateSampled
	p.KeepRate = &rate
	observed := c.observedPackets
	p.ObservedPackets = &observed
	if partial {
		up, srcs := c.sourcesUp, c.sourcesTotal
		p.SourcesUp, p.SourcesTotal = &up, &srcs
	}
	return p
}

// bucketTotals sums a rollup table into one row per bucket.
func (s *Store) bucketTotals(ctx context.Context, table string, from, to time.Time) (map[int64]TimePoint, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT bucket_ms, SUM(bytes), SUM(packets), SUM(flows), %s, %s
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ?
		GROUP BY bucket_ms`, directionSum(egressExpr), directionSum(ingressExpr), table),
		toMs(from), toMs(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[int64]TimePoint)
	for rows.Next() {
		var ms int64
		var p TimePoint
		var outB, inB sql.NullInt64
		if err := rows.Scan(&ms, &p.Bytes, &p.Packets, &p.Flows, &outB, &inB); err != nil {
			return nil, err
		}
		p.Time = fromMs(ms)
		p.OutBytes, p.InBytes = nullInt(outB), nullInt(inB)
		out[ms] = p
	}
	return out, rows.Err()
}

// nullInt turns SQL NULL into a nil pointer, which is how "not recorded"
// travels the whole way to the JSON: a *int64 that is nil is omitted, and a
// client cannot mistake an absent key for a zero the way it can mistake a
// zero-valued one.
func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// Talker is a source or destination ranked by traffic volume.
type Talker struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Flows   int64  `json:"flows"`
	// OutBytes is what Address sent and InBytes what it received — always from
	// the perspective of Address itself, whichever end of the flow it sat on,
	// so one reading serves every query that returns a Talker. They sum to
	// Bytes, and are nil together when any row behind the total predates
	// migration 0011 and recorded no direction. Nil is "not recorded"; it is
	// never a zero.
	OutBytes *int64 `json:"out_bytes,omitempty"`
	InBytes  *int64 `json:"in_bytes,omitempty"`
}

// talkerDirection builds the sent/received expressions for a query grouped by
// addrCol. Which half of a rollup row belongs to the address turns on whether
// the address is that row's source, so the two swap with the grouping column —
// getting it backwards would label a host being scanned as the one doing the
// talking.
func talkerDirection(addrCol string) (sent, received string) {
	if addrCol == "src_ip" {
		return directionSum("out_bytes"), directionSum("bytes - out_bytes")
	}
	return directionSum("bytes - out_bytes"), directionSum("out_bytes")
}

// TopTalkers returns the busiest sources between from and to, most bytes
// first, limited to n rows.
func (s *Store) TopTalkers(ctx context.Context, from, to time.Time, res Resolution, n int) ([]Talker, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	sent, received := talkerDirection("src_ip")
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT src_ip, SUM(bytes), SUM(packets), SUM(flows), %s, %s
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ?
		GROUP BY src_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, sent, received, table),
		toMs(from), toMs(to), n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Talker
	for rows.Next() {
		t, err := scanTalker(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// scanTalker reads one ranked row in the column order every Talker query above
// uses. Shared so the direction columns cannot be scanned in one order here
// and the opposite order there — a swap that produces plausible numbers and no
// error.
func scanTalker(rows *sql.Rows) (Talker, error) {
	var t Talker
	var outB, inB sql.NullInt64
	if err := rows.Scan(&t.Address, &t.Bytes, &t.Packets, &t.Flows, &outB, &inB); err != nil {
		return Talker{}, err
	}
	t.OutBytes, t.InBytes = nullInt(outB), nullInt(inB)
	return t, nil
}

// TopExternal returns the busiest external peers for one traffic direction:
// destinations for lan_wan (where is my traffic going), sources for wan_lan
// (who is knocking). Used by the country statistics, which aggregate the rows
// by GeoIP in the API layer.
func (s *Store) TopExternal(ctx context.Context, from, to time.Time, res Resolution, dir string, n int) ([]Talker, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	col := "dst_ip"
	if dir == "wan_lan" {
		col = "src_ip"
	}
	sent, received := talkerDirection(col)
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s, SUM(bytes), SUM(packets), SUM(flows), %s, %s
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND direction = ?
		GROUP BY %s
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, col, sent, received, table, col),
		toMs(from), toMs(to), dir, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Talker
	for rows.Next() {
		t, err := scanTalker(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountFlows returns the number of raw flow rows currently stored (used by
// tests and the system view).
func (s *Store) CountFlows(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flows`).Scan(&n)
	return n, err
}

// SearchFilter narrows a flow search. Empty fields are ignored, so the same
// query serves "everything from this device" and "port 22 in the last hour".
type SearchFilter struct {
	From, To time.Time
	// Address matches either endpoint; a bare IP or a CIDR.
	Address string
	Port    int
	Proto   string
	Dir     string
	// Name matches the resolved destination name, as a substring.
	Name  string
	Limit int
}

// searchScanCap bounds how many rows a subnet search examines. A CIDR cannot
// be tested in SQL, so the rows have to be walked — and this database serves
// every query through a single connection, so an unbounded walk over a wide
// window would stall flow writes along with the rest of the dashboard.
const searchScanCap = 200000

// SearchFlows returns raw flows matching the filter, newest first, and whether
// more matches exist beyond what is returned. Built for the question "what
// actually happened at 3am", which the aggregated views cannot answer — so a
// capped answer must never be presented as a complete one.
func (s *Store) SearchFlows(ctx context.Context, f SearchFilter) ([]model.Flow, bool, error) {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	q := `SELECT start_ms, end_ms, src_ip, dst_ip, src_port, dst_port, proto, direction,
	             out_bytes, out_packets, in_bytes, in_packets, dst_name
	      FROM flows WHERE start_ms >= ? AND start_ms < ?`
	args := []any{toMs(f.From), toMs(f.To)}

	if f.Address != "" {
		if _, err := netip.ParsePrefix(f.Address); err == nil {
			// A range: comparing the text form's prefix is wrong, so it is
			// filtered in Go below and the SQL is left open here.
		} else if _, err := netip.ParseAddr(f.Address); err == nil {
			q += ` AND (src_ip = ? OR dst_ip = ?)`
			args = append(args, f.Address, f.Address)
		} else {
			return nil, false, fmt.Errorf("store: %q is not an address or CIDR", f.Address)
		}
	}
	if f.Port > 0 {
		q += ` AND (src_port = ? OR dst_port = ?)`
		args = append(args, f.Port, f.Port)
	}
	if f.Proto != "" {
		// Protocols are stored numerically, as on the wire.
		var n uint8
		switch strings.ToLower(f.Proto) {
		case "tcp":
			n = uint8(model.ProtoTCP)
		case "udp":
			n = uint8(model.ProtoUDP)
		case "icmp":
			n = uint8(model.ProtoICMP)
		default:
			return nil, false, fmt.Errorf("store: unknown protocol %q", f.Proto)
		}
		q += ` AND proto = ?`
		args = append(args, n)
	}
	if f.Dir != "" {
		q += ` AND direction = ?`
		args = append(args, f.Dir)
	}
	if f.Name != "" {
		q += ` AND dst_name LIKE ?`
		args = append(args, "%"+f.Name+"%")
	}
	// A CIDR filter is applied in Go: SQLite has no network types, and the
	// alternative — a text prefix match — would be wrong at every boundary
	// that is not a byte boundary.
	var cidr netip.Prefix
	if f.Address != "" {
		if p, err := netip.ParsePrefix(f.Address); err == nil {
			cidr = p
		}
	}

	// When the filter runs in Go, the limit cannot also be in SQL. It used to
	// be, so a subnet search fetched the newest f.Limit flows regardless of
	// address, discarded the ones outside the range, and reported "Nothing
	// matched" while the matches sat just past the cut. That is a false
	// negative handed to someone in the middle of an investigation — the worst
	// possible moment to be told nothing happened. Scan instead, and stop once
	// enough matches are in hand; scanCap bounds the work so a wide window
	// cannot hold the single database connection indefinitely.
	q += ` ORDER BY start_ms DESC`
	if !cidr.IsValid() {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	} else {
		q += ` LIMIT ?`
		args = append(args, searchScanCap)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()

	scanned := 0
	var out []model.Flow
	for rows.Next() {
		var (
			fl            model.Flow
			start, end    int64
			src, dst, dir string
			proto         uint8
		)
		if err := rows.Scan(&start, &end, &src, &dst, &fl.SrcPort, &fl.DstPort, &proto, &dir,
			&fl.OutBytes, &fl.OutPackets, &fl.InBytes, &fl.InPackets, &fl.DstName); err != nil {
			return nil, false, err
		}
		scanned++
		fl.Start, fl.End = fromMs(start), fromMs(end)
		fl.SrcIP, _ = netip.ParseAddr(src)
		fl.DstIP, _ = netip.ParseAddr(dst)
		fl.Proto = model.Protocol(proto)
		fl.Dir = model.Direction(dir)
		if cidr.IsValid() && !cidr.Contains(fl.SrcIP.Unmap()) && !cidr.Contains(fl.DstIP.Unmap()) {
			continue
		}
		out = append(out, fl)
		if len(out) >= f.Limit {
			// More may match beyond this point; say so rather than let the
			// caller present a capped answer as a complete one.
			return out, true, rows.Err()
		}
	}
	// Hitting the scan cap means the window was not fully examined.
	return out, cidr.IsValid() && scanned >= searchScanCap, rows.Err()
}
