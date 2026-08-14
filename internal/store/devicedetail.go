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
	var ip, ip6 string
	var watch, present int
	var policy string
	var first, last int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, mac, ip, ip6, label, hostname, vendor, watch_presence, present, policy, first_seen_ms, last_seen_ms
		FROM devices WHERE mac = ?`, mac).
		Scan(&d.ID, &d.MAC, &ip, &ip6, &d.Label, &d.Hostname, &d.Vendor, &watch, &present, &policy, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return model.Device{}, err
	}
	d.IP, _ = netip.ParseAddr(ip)
	d.IP6, _ = netip.ParseAddr(ip6)
	d.WatchPresence = watch != 0
	d.Present = present != 0
	d.Policy = model.DevicePolicy(policy)
	d.FirstSeen = fromMs(first)
	d.LastSeen = fromMs(last)
	return d, nil
}

// DeviceThroughput returns the device's traffic per bucket — everything it
// sent or received — from the rollup at the given resolution.
// It returns a dense series for the same reason the network-wide one does:
// handing a chart only the buckets that had traffic lets it join what is left
// with a straight line, so an afternoon with the capture down looks like an
// afternoon of steady traffic.
func (s *Store) DeviceThroughput(ctx context.Context, ip string, from, to time.Time, res Resolution) (Series, error) {
	table, size, err := res.table()
	if err != nil {
		return Series{}, err
	}
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

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT bucket_ms, SUM(bytes), SUM(packets), SUM(flows), %s, %s
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND (src_ip = ? OR dst_ip = ?)
		GROUP BY bucket_ms`,
		directionSum(subjectSentExpr), directionSum(subjectRecvExpr), table),
		ip, ip, toMs(start), toMs(end), ip, ip)
	if err != nil {
		return Series{}, err
	}
	defer func() { _ = rows.Close() }()

	totals := map[int64]TimePoint{}
	for rows.Next() {
		var ms int64
		var p TimePoint
		var outB, inB sql.NullInt64
		if err := rows.Scan(&ms, &p.Bytes, &p.Packets, &p.Flows, &outB, &inB); err != nil {
			return Series{}, err
		}
		p.OutBytes, p.InBytes = nullInt(outB), nullInt(inB)
		totals[ms] = p
	}
	if err := rows.Err(); err != nil {
		return Series{}, err
	}
	return s.densify(ctx, totals, start, end, to, size, res, n)
}

// DeviceDestinations returns where the device talked to, busiest first. Names
// come from the raw flows' DNS/SNI enrichment where one was ever captured for
// that destination.
func (s *Store) DeviceDestinations(ctx context.Context, ip string, from, to time.Time, res Resolution, n int) ([]Talker, error) {
	table, _, err := res.table()
	if err != nil {
		return nil, err
	}
	sent, received := talkerDirection("dst_ip")
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT dst_ip, SUM(bytes), SUM(packets), SUM(flows), %s, %s
		FROM %s
		WHERE bucket_ms >= ? AND bucket_ms < ? AND src_ip = ?
		GROUP BY dst_ip
		ORDER BY SUM(bytes) DESC
		LIMIT ?`, sent, received, table),
		toMs(from), toMs(to), ip, n)
	if err != nil {
		return nil, err
	}
	var out []Talker
	for rows.Next() {
		t, err := scanTalker(rows)
		if err != nil {
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

// NamingSplit is how much of a device's traffic to the internet went somewhere
// Skopos was ever able to put a name to. It is the closest honest measurement
// of the blind spot a device creates by resolving its own names — a TV with a
// hard-coded resolver or DoH leaves no DNS for the capture to read, so its
// destinations stay bare addresses no matter how long it runs.
type NamingSplit struct {
	// NamedBytes and UnnamedBytes are bytes the device sent, not conversation
	// totals: the question is what it uploaded and where, and a reply counts
	// toward neither.
	NamedBytes   int64 `json:"named_bytes"`
	UnnamedBytes int64 `json:"unnamed_bytes"`
	// WindowFrom is where the answer really begins and WindowDays how long that
	// is, both derived from the oldest raw flow still on disk rather than from
	// the retention setting. EnforceHotLimit deletes raw flows first when the
	// hot cap is hit, so the configured seven days is a ceiling and routinely
	// not what survived. A share printed without this is quietly claimed to be
	// "all time".
	WindowFrom time.Time `json:"window_from"`
	WindowDays float64   `json:"window_days"`
	// Truncated is set when the caller asked about a period that reaches back
	// further than the surviving flows do.
	Truncated bool `json:"truncated"`
}

// DeviceNaming measures the named/unnamed split of one device's egress over
// the raw-flow window, which is the only place a per-flow name exists — the
// rollups never carried dst_name.
//
// It reports a measurement, not a verdict. A flow whose name arrived after it
// started, or that began before the resolver map was warm, counts as unnamed,
// which biases the number upward: the honest reading is "could not name",
// never "the device hid it".
func (s *Store) DeviceNaming(ctx context.Context, ip string, from, to time.Time) (NamingSplit, error) {
	var out NamingSplit

	// Only traffic that left the network. Local chatter has mDNS names the
	// device never asked a resolver for, and counting it would dilute exactly
	// the signal this is here to show.
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(CASE WHEN dst_name != '' THEN out_bytes ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN dst_name  = '' THEN out_bytes ELSE 0 END), 0)
		FROM flows
		WHERE src_ip = ? AND start_ms >= ? AND start_ms < ? AND direction = ?`,
		ip, toMs(from), toMs(to), string(model.DirLANtoWAN)).
		Scan(&out.NamedBytes, &out.UnnamedBytes)
	if err != nil {
		return NamingSplit{}, err
	}

	var oldest sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(start_ms) FROM flows`).Scan(&oldest); err != nil {
		return NamingSplit{}, err
	}
	out.WindowFrom = from
	if !oldest.Valid {
		// No raw flows at all: the window this can answer over is empty, and
		// saying so is different from answering "0 % unnamed" over seven days.
		out.WindowFrom, out.Truncated = to, true
	} else if o := fromMs(oldest.Int64); o.After(from) {
		out.WindowFrom, out.Truncated = o, true
	}
	if d := to.Sub(out.WindowFrom); d > 0 {
		out.WindowDays = d.Hours() / 24
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
