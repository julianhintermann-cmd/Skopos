package store

import (
	"fmt"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// bucket truncates t to the start of the interval d in UTC.
func bucket(t time.Time, d time.Duration) time.Time {
	return t.UTC().Truncate(d)
}

const (
	bucket1m = time.Minute
	bucket1h = time.Hour
	bucket1d = 24 * time.Hour
)

// WriteFlows persists a batch of aggregated flows and folds them into the
// three rollup resolutions in a single transaction. Callers (the flow
// aggregator) hand over one flush interval's worth of flows at a time.
//
// Raw flows serve short-window detection and forensic drill-down; the rollups
// answer every dashboard time-series query without ever scanning raw rows,
// which is what keeps the database fast as history grows.
func (s *Store) WriteFlows(flows []model.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	insRaw, err := tx.Prepare(`INSERT INTO flows
		(start_ms, end_ms, src_ip, dst_ip, src_port, dst_port, proto, direction,
		 out_bytes, out_packets, in_bytes, in_packets, dst_name)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer func() { _ = insRaw.Close() }()

	// Upsert-accumulate into each rollup: repeated tuples in the same bucket
	// add up instead of colliding.
	upsert := func(table string, b time.Time, f model.Flow) error {
		_, err := tx.Exec(fmt.Sprintf(`INSERT INTO %s
			(bucket_ms, src_ip, dst_ip, dst_port, proto, direction, bytes, packets, flows)
			VALUES (?,?,?,?,?,?,?,?,1)
			ON CONFLICT(bucket_ms, src_ip, dst_ip, dst_port, proto, direction)
			DO UPDATE SET bytes = bytes + excluded.bytes,
			              packets = packets + excluded.packets,
			              flows = flows + 1`, table),
			toMs(b), f.SrcIP.String(), f.DstIP.String(), f.DstPort, uint8(f.Proto),
			string(f.Dir), f.Bytes(), f.Packets())
		return err
	}

	for _, f := range flows {
		if _, err := insRaw.Exec(
			toMs(f.Start), toMs(f.End), f.SrcIP.String(), f.DstIP.String(),
			f.SrcPort, f.DstPort, uint8(f.Proto), string(f.Dir),
			f.OutBytes, f.OutPackets, f.InBytes, f.InPackets, f.DstName,
		); err != nil {
			return fmt.Errorf("insert flow: %w", err)
		}
		for _, r := range []struct {
			table string
			size  time.Duration
		}{{"rollup_1m", bucket1m}, {"rollup_1h", bucket1h}, {"rollup_1d", bucket1d}} {
			if err := upsert(r.table, bucket(f.Start, r.size), f); err != nil {
				return fmt.Errorf("rollup %s: %w", r.table, err)
			}
		}
	}
	return tx.Commit()
}
