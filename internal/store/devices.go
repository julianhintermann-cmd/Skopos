package store

import (
	"context"
	"errors"
	"net/netip"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// UpsertDevice records or refreshes a LAN device by MAC. It returns whether
// the device was newly created, which the new-device detector uses to decide
// whether to raise an alert. First-seen time is preserved across updates.
//
// The insert-or-update runs in one transaction with an explicit existence
// check so "is new" is correct even under a fixed clock (where comparing
// timestamps would not tell an insert from an update).
func (s *Store) UpsertDevice(ctx context.Context, mac, ip, hostname, vendor string) (isNew bool, err error) {
	now := toMs(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE mac = ?)`, mac).Scan(&exists)
	if err != nil {
		return false, err
	}

	if exists {
		if _, err := tx.ExecContext(ctx, `
			UPDATE devices SET
				ip       = CASE WHEN ? != '' THEN ? ELSE ip END,
				hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
				vendor   = CASE WHEN ? != '' THEN ? ELSE vendor END,
				last_seen_ms = ?
			WHERE mac = ?`,
			ip, ip, hostname, hostname, vendor, vendor, now, mac); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devices (mac, ip, hostname, vendor, first_seen_ms, last_seen_ms)
			VALUES (?,?,?,?,?,?)`,
			mac, ip, hostname, vendor, now, now); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return !exists, nil
}

// ListDevices returns known devices, most recently seen first.
func (s *Store) ListDevices(ctx context.Context) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, mac, ip, label, hostname, vendor, first_seen_ms, last_seen_ms
		FROM devices ORDER BY last_seen_ms DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Device
	for rows.Next() {
		var d model.Device
		var ip string
		var first, last int64
		if err := rows.Scan(&d.ID, &d.MAC, &ip, &d.Label, &d.Hostname, &d.Vendor, &first, &last); err != nil {
			return nil, err
		}
		d.IP, _ = netip.ParseAddr(ip)
		d.FirstSeen = fromMs(first)
		d.LastSeen = fromMs(last)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ErrDeviceNotFound is returned by SetDeviceLabel when no device carries the
// given MAC.
var ErrDeviceNotFound = errors.New("device not found")

// SetDeviceLabel assigns (or, with an empty label, clears) the operator label
// for the device with the given MAC. The label is left untouched by
// UpsertDevice, so auto-discovery never overwrites it.
func (s *Store) SetDeviceLabel(ctx context.Context, mac, label string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET label = ? WHERE mac = ?`, label, mac)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}
