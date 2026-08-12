package store

import (
	"context"
	"time"
)

// SumBytes returns the total traffic volume in [from, to) from the hourly
// rollup — the report's headline number.
func (s *Store) SumBytes(ctx context.Context, from, to time.Time) (int64, error) {
	var total int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(bytes), 0) FROM rollup_1h
		WHERE bucket_ms >= ? AND bucket_ms < ?`,
		toMs(from), toMs(to)).Scan(&total)
	return total, err
}

// AlertCountsSince returns how many alerts each detector raised since t,
// weighting aggregated alerts by their occurrence count.
func (s *Store) AlertCountsSince(ctx context.Context, t time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT detector, SUM(count) FROM alerts
		WHERE time_ms >= ? GROUP BY detector`, toMs(t))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		out[d] = n
	}
	return out, rows.Err()
}

// CountDevicesSince returns how many devices were first seen since t.
func (s *Store) CountDevicesSince(ctx context.Context, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE first_seen_ms >= ?`, toMs(t)).Scan(&n)
	return n, err
}
