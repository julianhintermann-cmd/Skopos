package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// DeviceByMAC returns the inventory record for one device.
func (s *Store) DeviceByMAC(ctx context.Context, mac string) (model.Device, error) {
	var d model.Device
	var ip string
	var watch, present int
	var first, last int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, mac, ip, label, hostname, vendor, watch_presence, present, first_seen_ms, last_seen_ms
		FROM devices WHERE mac = ?`, mac).
		Scan(&d.ID, &d.MAC, &ip, &d.Label, &d.Hostname, &d.Vendor, &watch, &present, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return model.Device{}, err
	}
	d.IP, _ = netip.ParseAddr(ip)
	d.WatchPresence = watch != 0
	d.Present = present != 0
	d.FirstSeen = fromMs(first)
	d.LastSeen = fromMs(last)
	return d, nil
}

// DeviceThroughput returns the device's traffic per bucket — everything it
// sent or received — from the rollup at the given resolution.
func (s *Store) DeviceThroughput(ctx context.Context, ip string, from, to time.Time, res Resolution) ([]TimePoint, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT bucket_ms, SUM(bytes), SUM(packets), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND (src_ip = ? OR dst_ip = ?)
		GROUP BY bucket_ms
		ORDER BY bucket_ms`, table),
		toMs(from), toMs(to), ip, ip)
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

// DeviceDestinations returns where the device talked to, busiest first. Names
// come from the raw flows' DNS/SNI enrichment where one was ever captured for
// that destination.
func (s *Store) DeviceDestinations(ctx context.Context, ip string, from, to time.Time, res Resolution, n int) ([]Talker, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT dst_ip, SUM(bytes), SUM(packets), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND src_ip = ?
		GROUP BY dst_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, table),
		toMs(from), toMs(to), ip, n)
	if err != nil {
		return nil, err
	}
	var out []Talker
	for rows.Next() {
		var t Talker
		if err := rows.Scan(&t.Address, &t.Bytes, &t.Packets, &t.Flows); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}

	// Enrich with the most recently seen DNS/SNI name per destination.
	names, err := s.db.QueryContext(ctx, `
		SELECT dst_ip, dst_name FROM flows
		WHERE src_ip = ? AND dst_name != '' AND start_ms >= ?
		GROUP BY dst_ip HAVING MAX(end_ms)`,
		ip, toMs(from))
	if err != nil {
		return out, nil // enrichment is best-effort
	}
	defer func() { _ = names.Close() }()
	byIP := map[string]string{}
	for names.Next() {
		var dst, name string
		if err := names.Scan(&dst, &name); err == nil {
			byIP[dst] = name
		}
	}
	for i := range out {
		out[i].Name = byIP[out[i].Address]
	}
	return out, nil
}

// PortUsage is one (port, protocol) the device used, by volume.
type PortUsage struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	Bytes int64  `json:"bytes"`
	Flows int64  `json:"flows"`
}

// DevicePorts returns the destination ports the device talked to, busiest
// first — the quickest read on what a machine actually does.
func (s *Store) DevicePorts(ctx context.Context, ip string, from, to time.Time, res Resolution, n int) ([]PortUsage, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT dst_port, proto, SUM(bytes), SUM(flows)
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND src_ip = ?
		GROUP BY dst_port, proto
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, table),
		toMs(from), toMs(to), ip, n)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []PortUsage
	for rows.Next() {
		var p PortUsage
		var proto uint8
		if err := rows.Scan(&p.Port, &proto, &p.Bytes, &p.Flows); err != nil {
			return nil, err
		}
		p.Proto = model.Protocol(proto).String()
		out = append(out, p)
	}
	return out, rows.Err()
}
