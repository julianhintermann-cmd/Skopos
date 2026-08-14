package store

import (
	"context"
	"fmt"
	"net/netip"
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
	//
	// out_bytes is added plainly rather than through COALESCE, so NULL wins.
	// A bucket that already existed when migration 0011 ran holds bytes whose
	// direction was never recorded; folding today's split into it would produce
	// an out_bytes that covers part of the bucket and is presented as covering
	// all of it. Once unrecorded, the bucket stays unrecorded — for a 1m bucket
	// that is one minute of history, for the 1d rollup at most the day of the
	// upgrade.
	upsert := func(table string, b time.Time, f model.Flow) error {
		_, err := tx.Exec(fmt.Sprintf(`INSERT INTO %s
			(bucket_ms, src_ip, dst_ip, dst_port, proto, direction, bytes, packets, flows, out_bytes)
			VALUES (?,?,?,?,?,?,?,?,1,?)
			ON CONFLICT(bucket_ms, src_ip, dst_ip, dst_port, proto, direction)
			DO UPDATE SET bytes = bytes + excluded.bytes,
			              packets = packets + excluded.packets,
			              flows = flows + 1,
			              out_bytes = out_bytes + excluded.out_bytes`, table),
			toMs(b), f.SrcIP.String(), f.DstIP.String(), f.DstPort, uint8(f.Proto),
			string(f.Dir), f.Bytes(), f.Packets(), f.OutBytes)
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

// ExportFlows returns raw flows whose start falls in [from, to), newest first,
// capped at limit rows. It backs the CSV export; dashboards use the rollups.
func (s *Store) ExportFlows(ctx context.Context, from, to time.Time, limit int) ([]model.Flow, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT start_ms, end_ms, src_ip, dst_ip, src_port, dst_port, proto, direction,
		       out_bytes, out_packets, in_bytes, in_packets, dst_name
		FROM flows
		WHERE start_ms >= ? AND start_ms < ?
		ORDER BY start_ms DESC LIMIT ?`,
		toMs(from), toMs(to), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Flow
	for rows.Next() {
		var f model.Flow
		var start, end int64
		var src, dst, dir string
		var proto uint8
		if err := rows.Scan(&start, &end, &src, &dst, &f.SrcPort, &f.DstPort, &proto, &dir,
			&f.OutBytes, &f.OutPackets, &f.InBytes, &f.InPackets, &f.DstName); err != nil {
			return nil, err
		}
		f.Start = fromMs(start)
		f.End = fromMs(end)
		f.SrcIP, _ = netip.ParseAddr(src)
		f.DstIP, _ = netip.ParseAddr(dst)
		f.Proto = model.Protocol(proto)
		f.Dir = model.Direction(dir)
		out = append(out, f)
	}
	return out, rows.Err()
}
