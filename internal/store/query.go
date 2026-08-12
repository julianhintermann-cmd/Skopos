package store

import (
	"context"
	"fmt"
	"time"
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

// CountFlows returns the number of raw flow rows currently stored (used by
// tests and the system view).
func (s *Store) CountFlows(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flows`).Scan(&n)
	return n, err
}
