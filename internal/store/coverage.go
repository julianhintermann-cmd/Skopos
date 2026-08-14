package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// coverageTable names the coverage table for a resolution and the number of
// seconds a full bucket holds.
func (r Resolution) coverageTable() (string, int, error) {
	switch r {
	case Res1m:
		return "coverage_1m", int(bucket1m / time.Second), nil
	case Res1h:
		return "coverage_1h", int(bucket1h / time.Second), nil
	case Res1d:
		return "coverage_1d", int(bucket1d / time.Second), nil
	default:
		return "", 0, fmt.Errorf("unknown resolution %q", r)
	}
}

// WriteCoverage records the capture heartbeat at all three resolutions, the
// same fan-out WriteFlows does for the rollups.
//
// Records accumulate: a one-minute bucket is assembled from however many
// flushes land inside it, and an hour from sixty minutes' worth. sources_up
// takes the minimum because "up for part of the bucket" is not up for the
// bucket, and seconds_covered is capped at the bucket length so a clock jump
// cannot manufacture more coverage than the bucket can hold.
func (s *Store) WriteCoverage(cov []model.Coverage) error {
	if len(cov) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, r := range []Resolution{Res1m, Res1h, Res1d} {
		table, full, err := r.coverageTable()
		if err != nil {
			return err
		}
		_, size, err := r.table()
		if err != nil {
			return err
		}
		stmt, err := tx.Prepare(fmt.Sprintf(`INSERT INTO %s
			(bucket_ms, sources_total, sources_up, observed_packets, kept_packets, seconds_covered)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(bucket_ms) DO UPDATE SET
			  sources_total    = MAX(sources_total, excluded.sources_total),
			  sources_up       = MIN(sources_up, excluded.sources_up),
			  observed_packets = observed_packets + excluded.observed_packets,
			  kept_packets     = kept_packets + excluded.kept_packets,
			  seconds_covered  = MIN(?, seconds_covered + excluded.seconds_covered)`, table))
		if err != nil {
			return err
		}
		for _, c := range cov {
			if _, err := stmt.Exec(
				toMs(bucket(c.Bucket, size)), c.SourcesTotal, c.SourcesUp,
				c.ObservedPackets, c.KeptPackets, c.SecondsCovered, full,
			); err != nil {
				_ = stmt.Close()
				return fmt.Errorf("coverage %s: %w", table, err)
			}
		}
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// coverageRow is one stored bucket of capture coverage.
type coverageRow struct {
	sourcesTotal    int
	sourcesUp       int
	observedPackets int64
	keptPackets     int64
	secondsCovered  int
}

// keepRate is the realized fraction of packets that survived sampling. A
// bucket that observed nothing sampled nothing, so its rate is 1: there is no
// undercount to correct for.
func (c coverageRow) keepRate() float64 {
	if c.observedPackets <= 0 || c.keptPackets >= c.observedPackets {
		return 1
	}
	return float64(c.keptPackets) / float64(c.observedPackets)
}

// coverage reads the recorded coverage for a range, keyed by bucket, together
// with the first bucket ever recorded at this resolution.
//
// That horizon is what keeps pre-0.4.0 history honest: before it, nothing was
// recorded about the capture, so those buckets are "not recorded" rather than
// silently promoted to verified-complete. When the table is empty there is no
// horizon at all and the caller falls back to what the rollups alone can say.
func (s *Store) coverage(ctx context.Context, from, to time.Time, res Resolution) (rows map[int64]coverageRow, horizon int64, ok bool, err error) {
	table, _, err := res.coverageTable()
	if err != nil {
		return nil, 0, false, err
	}

	var first sql.NullInt64
	if err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT MIN(bucket_ms) FROM %s`, table)).Scan(&first); err != nil {
		return nil, 0, false, err
	}
	if !first.Valid {
		return nil, 0, false, nil
	}

	q, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT bucket_ms, sources_total, sources_up, observed_packets, kept_packets, seconds_covered
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ?`, table),
		toMs(from), toMs(to))
	if err != nil {
		return nil, 0, false, err
	}
	defer func() { _ = q.Close() }()

	rows = make(map[int64]coverageRow)
	for q.Next() {
		var ms int64
		var c coverageRow
		if err := q.Scan(&ms, &c.sourcesTotal, &c.sourcesUp,
			&c.observedPackets, &c.keptPackets, &c.secondsCovered); err != nil {
			return nil, 0, false, err
		}
		rows[ms] = c
	}
	return rows, first.Int64, true, q.Err()
}
