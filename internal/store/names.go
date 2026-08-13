package store

import (
	"context"
	"time"
)

// NameObservation is one address→name mapping to record.
type NameObservation struct {
	IP     string
	Name   string
	Source string // "dns", "mdns" or "sni"
	Time   time.Time
}

// DomainContact is one device's traffic to one domain within an hour.
type DomainContact struct {
	HourMs   int64
	DeviceIP string
	Name     string
	Flows    int64
	Bytes    int64
}

// FingerprintObservation is one JA4 seen from a device.
type FingerprintObservation struct {
	DeviceIP string
	JA4      string
	Time     time.Time
}

// UpsertNames records address→name mappings, bumping hit counts for ones
// already known. Written in a single transaction because the resolver
// flushes a batch at a time.
func (s *Store) UpsertNames(ctx context.Context, obs []NameObservation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO dns_names (ip, name, source, first_ms, last_ms, hits)
		VALUES (?,?,?,?,?,1)
		ON CONFLICT(ip, name) DO UPDATE SET
			last_ms = excluded.last_ms,
			hits    = dns_names.hits + 1,
			source  = excluded.source`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, o := range obs {
		ms := toMs(o.Time)
		if _, err := stmt.ExecContext(ctx, o.IP, o.Name, o.Source, ms, ms); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddDomainContacts accumulates per-device, per-hour domain traffic.
func (s *Store) AddDomainContacts(ctx context.Context, contacts []DomainContact) error {
	if len(contacts) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO domain_contacts (hour_ms, device_ip, name, flows, bytes)
		VALUES (?,?,?,?,?)
		ON CONFLICT(hour_ms, device_ip, name) DO UPDATE SET
			flows = domain_contacts.flows + excluded.flows,
			bytes = domain_contacts.bytes + excluded.bytes`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, c := range contacts {
		if _, err := stmt.ExecContext(ctx, c.HourMs, c.DeviceIP, c.Name, c.Flows, c.Bytes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpsertFingerprints records JA4 client fingerprints per device.
func (s *Store) UpsertFingerprints(ctx context.Context, obs []FingerprintObservation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO tls_fingerprints (device_ip, ja4, first_ms, last_ms, hits)
		VALUES (?,?,?,?,1)
		ON CONFLICT(device_ip, ja4) DO UPDATE SET
			last_ms = excluded.last_ms,
			hits    = tls_fingerprints.hits + 1`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, o := range obs {
		ms := toMs(o.Time)
		if _, err := stmt.ExecContext(ctx, o.DeviceIP, o.JA4, ms, ms); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// KnownNames loads the persisted address→name map so the resolver starts warm
// after a restart instead of forgetting every name.
func (s *Store) KnownNames(ctx context.Context, limit int) (map[string]string, error) {
	if limit <= 0 {
		limit = 20000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, name FROM dns_names
		ORDER BY last_ms DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]string)
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return nil, err
		}
		// Newest wins: the first row for an address is its freshest name.
		if _, ok := out[ip]; !ok {
			out[ip] = name
		}
	}
	return out, rows.Err()
}

// DomainStat is one domain's share of traffic in a window.
type DomainStat struct {
	Name     string `json:"name"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	Devices  int64  `json:"devices"`
	DeviceIP string `json:"device_ip,omitempty"`
}

// TopDomains aggregates domain traffic over a window, newest-heavy first.
// A device IP narrows it to one device's domains.
func (s *Store) TopDomains(ctx context.Context, from, to time.Time, deviceIP string, limit int) ([]DomainStat, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT name, SUM(flows), SUM(bytes), COUNT(DISTINCT device_ip)
		FROM domain_contacts
		WHERE hour_ms >= ? AND hour_ms < ?`
	args := []any{toMs(from), toMs(to)}
	if deviceIP != "" {
		query += ` AND device_ip = ?`
		args = append(args, deviceIP)
	}
	query += ` GROUP BY name ORDER BY SUM(bytes) DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []DomainStat
	for rows.Next() {
		var d DomainStat
		if err := rows.Scan(&d.Name, &d.Flows, &d.Bytes, &d.Devices); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeviceFingerprints returns the JA4 fingerprints seen from a device.
type Fingerprint struct {
	JA4   string    `json:"ja4"`
	Hits  int64     `json:"hits"`
	First time.Time `json:"first_seen"`
	Last  time.Time `json:"last_seen"`
}

// DeviceFingerprints lists a device's TLS client fingerprints, busiest first.
func (s *Store) DeviceFingerprints(ctx context.Context, deviceIP string, limit int) ([]Fingerprint, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ja4, hits, first_ms, last_ms FROM tls_fingerprints
		WHERE device_ip = ? ORDER BY hits DESC LIMIT ?`, deviceIP, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Fingerprint
	for rows.Next() {
		var f Fingerprint
		var first, last int64
		if err := rows.Scan(&f.JA4, &f.Hits, &first, &last); err != nil {
			return nil, err
		}
		f.First, f.Last = fromMs(first), fromMs(last)
		out = append(out, f)
	}
	return out, rows.Err()
}

// PruneNames drops name and contact history older than the cutoff, keeping
// the passive-DNS tables from growing without bound.
func (s *Store) PruneNames(ctx context.Context, before time.Time) error {
	ms := toMs(before)
	for _, q := range []string{
		`DELETE FROM dns_names WHERE last_ms < ?`,
		`DELETE FROM domain_contacts WHERE hour_ms < ?`,
		`DELETE FROM tls_fingerprints WHERE last_ms < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, ms); err != nil {
			return err
		}
	}
	return nil
}
