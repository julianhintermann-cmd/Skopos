package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

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
	return s.queryDevices(ctx, `ORDER BY last_seen_ms DESC`)
}

// WatchedDevices returns devices with presence tracking enabled.
func (s *Store) WatchedDevices(ctx context.Context) ([]model.Device, error) {
	return s.queryDevices(ctx, `WHERE watch_presence = 1 ORDER BY last_seen_ms DESC`)
}

func (s *Store) queryDevices(ctx context.Context, tail string) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, mac, ip, label, hostname, vendor, watch_presence, present, first_seen_ms, last_seen_ms
		FROM devices `+tail)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Device
	for rows.Next() {
		var d model.Device
		var ip string
		var watch, present int
		var first, last int64
		if err := rows.Scan(&d.ID, &d.MAC, &ip, &d.Label, &d.Hostname, &d.Vendor, &watch, &present, &first, &last); err != nil {
			return nil, err
		}
		d.IP, _ = netip.ParseAddr(ip)
		d.WatchPresence = watch != 0
		d.Present = present != 0
		d.FirstSeen = fromMs(first)
		d.LastSeen = fromMs(last)
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDeviceWatchPresence toggles presence tracking. Enabling seeds the present
// state from how recently the device was seen, so the first tracker pass does
// not immediately fire an arrival or departure for a device that never moved.
func (s *Store) SetDeviceWatchPresence(ctx context.Context, mac string, watch bool, seenWithin time.Duration) error {
	present := 0
	if watch {
		cutoff := toMs(s.now().Add(-seenWithin))
		res, err := s.db.ExecContext(ctx, `
			UPDATE devices SET watch_presence = 1,
			                   present = CASE WHEN last_seen_ms >= ? THEN 1 ELSE 0 END
			WHERE mac = ?`, cutoff, mac)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrDeviceNotFound
		}
		return nil
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET watch_presence = 0, present = ? WHERE mac = ?`, present, mac)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// SetDevicePresent records the tracker's new state for a device.
func (s *Store) SetDevicePresent(ctx context.Context, mac string, present bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE devices SET present = ? WHERE mac = ?`, boolToInt(present), mac)
	return err
}

// ErrDeviceNotFound is returned by SetDeviceLabel when no device carries the
// given MAC.
var ErrDeviceNotFound = errors.New("device not found")

// DeviceNameByIP returns the best display name (operator label, else
// discovered hostname) for the device currently holding ip, or "" when the
// address is unknown or nameless. Used to annotate notifications so an alert
// reads "192.168.1.23 (Living-room TV)" instead of a bare address.
func (s *Store) DeviceNameByIP(ctx context.Context, ip string) (string, error) {
	var label, hostname string
	err := s.db.QueryRowContext(ctx, `
		SELECT label, hostname FROM devices
		WHERE ip = ? ORDER BY last_seen_ms DESC LIMIT 1`, ip).Scan(&label, &hostname)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if label != "" {
		return label, nil
	}
	return hostname, nil
}

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
