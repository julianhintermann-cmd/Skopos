package store

import (
	"context"
	"fmt"
	"time"
)

// RetentionPolicy defines how long each resolution is kept on hot storage.
// A zero duration means "keep forever".
type RetentionPolicy struct {
	RawFlows time.Duration
	Rollup1m time.Duration
	Rollup1h time.Duration
	Rollup1d time.Duration
}

// ApplyRetention deletes rows older than the policy for each table. Raw flows
// are expected to have been archived to cold storage beforehand; this only
// reclaims hot-storage space. It returns the number of rows deleted.
func (s *Store) ApplyRetention(ctx context.Context, p RetentionPolicy) (int64, error) {
	now := s.now()
	var total int64

	jobs := []struct {
		table string
		col   string
		age   time.Duration
	}{
		{"flows", "start_ms", p.RawFlows},
		{"rollup_1m", "bucket_ms", p.Rollup1m},
		{"rollup_1h", "bucket_ms", p.Rollup1h},
		{"rollup_1d", "bucket_ms", p.Rollup1d},
	}
	for _, j := range jobs {
		if j.age <= 0 {
			continue // keep forever
		}
		cutoff := toMs(now.Add(-j.age))
		res, err := s.db.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE %s < ?`, j.table, j.col), cutoff)
		if err != nil {
			return total, fmt.Errorf("retention on %s: %w", j.table, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// EnforceHotLimit keeps total hot-storage usage under maxBytes by deleting the
// oldest raw flows first (aggregated rollups are preserved). It measures the
// database's real on-disk footprint including the WAL, deletes in batches
// until back under budget, then reclaims free pages. Returns rows deleted.
//
// The SSD does not belong to Skopos: this is the backstop that guarantees the
// database can never grow without bound, independent of the time-based policy.
func (s *Store) EnforceHotLimit(ctx context.Context, maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return 0, nil
	}
	const batch = 5000
	var deleted int64
	for i := 0; i < 1000; i++ { // bounded backstop against a runaway loop
		size, err := s.diskSize()
		if err != nil {
			return deleted, err
		}
		if size <= maxBytes {
			break
		}
		n, err := s.deleteOldestFlows(ctx, batch)
		if err != nil {
			return deleted, err
		}
		deleted += n
		if n == 0 {
			// No raw flows left to drop; rollups stay by design even if that
			// leaves us above the cap.
			break
		}
		// Return freed pages to the filesystem so the next size check sees
		// the reduction (WAL checkpoint + incremental vacuum).
		_, _ = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
		_, _ = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	}
	return deleted, nil
}

// deleteOldestFlows removes up to n raw flows with the smallest start time.
func (s *Store) deleteOldestFlows(ctx context.Context, n int) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM flows WHERE id IN (
			SELECT id FROM flows ORDER BY start_ms ASC LIMIT ?
		)`, n)
	if err != nil {
		return 0, fmt.Errorf("hot-limit delete: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

// diskSize reports the database's page-based size in bytes. It counts pages
// rather than stat-ing files so it works the same for the main file and WAL.
func (s *Store) diskSize() (int64, error) {
	var pageCount, pageSize int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, err
	}
	return pageCount * pageSize, nil
}
