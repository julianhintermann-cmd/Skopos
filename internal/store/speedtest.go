package store

import (
	"context"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// InsertSpeedtest stores one measurement and returns it with its ID.
func (s *Store) InsertSpeedtest(ctx context.Context, r model.SpeedtestResult) (model.SpeedtestResult, error) {
	if r.Time.IsZero() {
		r.Time = s.now()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO speedtest_results (time_ms, down_mbps, up_mbps, latency_ms)
		VALUES (?,?,?,?)`,
		toMs(r.Time), r.DownMbps, r.UpMbps, r.LatencyMs)
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()

	// Keep the table bounded; the history chart never needs more.
	_, _ = s.db.ExecContext(ctx, `
		DELETE FROM speedtest_results WHERE id NOT IN (
			SELECT id FROM speedtest_results ORDER BY time_ms DESC LIMIT 500)`)
	return r, nil
}

// ListSpeedtests returns measurements oldest first (chart order), up to limit.
func (s *Store) ListSpeedtests(ctx context.Context, limit int) ([]model.SpeedtestResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, time_ms, down_mbps, up_mbps, latency_ms FROM (
			SELECT * FROM speedtest_results ORDER BY time_ms DESC LIMIT ?
		) ORDER BY time_ms ASC`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.SpeedtestResult
	for rows.Next() {
		var r model.SpeedtestResult
		var ms int64
		if err := rows.Scan(&r.ID, &ms, &r.DownMbps, &r.UpMbps, &r.LatencyMs); err != nil {
			return nil, err
		}
		r.Time = fromMs(ms)
		out = append(out, r)
	}
	return out, rows.Err()
}
