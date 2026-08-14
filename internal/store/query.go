package store

import (
	"context"
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
}

// Throughput returns total bytes/packets/flows per bucket between from and to
// (inclusive of from, exclusive of to) at the given resolution. Empty buckets
// are omitted; the caller fills gaps for charting.
func (s *Store) Throughput(ctx context.Context, from, to time.Time, res Resolution) ([]TimePoint, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT bucket_ms, SUM(bytes), SUM(packets), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ?
		GROUP BY bucket_ms
		ORDER BY bucket_ms`, table),
		toMs(from), toMs(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []TimePoint
	for rows.Next() {
		var ms int64
		var p TimePoint
		if err := rows.Scan(&ms, &p.Bytes, &p.Packets, &p.Flows); err != nil {
			return nil, err
		}
		p.Time = fromMs(ms)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Talker is a source or destination ranked by traffic volume.
type Talker struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Flows   int64  `json:"flows"`
}

// TopTalkers returns the busiest sources between from and to, most bytes
// first, limited to n rows.
func (s *Store) TopTalkers(ctx context.Context, from, to time.Time, res Resolution, n int) ([]Talker, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT src_ip, SUM(bytes), SUM(packets), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ?
		GROUP BY src_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, table),
		toMs(from), toMs(to), n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Talker
	for rows.Next() {
		var t Talker
		if err := rows.Scan(&t.Address, &t.Bytes, &t.Packets, &t.Flows); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
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
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s, SUM(bytes), SUM(packets), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND direction = ?
		GROUP BY %s
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, col, table, col),
		toMs(from), toMs(to), dir, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Talker
	for rows.Next() {
		var t Talker
		if err := rows.Scan(&t.Address, &t.Bytes, &t.Packets, &t.Flows); err != nil {
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
