package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// MaxMACsPerAddress caps how many inventory entries a single IP address may
// accumulate.
//
// One address, one machine — that is what makes a MAC/IP pairing worth
// recording. Some traffic breaks the assumption: a tunnel or virtual switch
// that presents synthetic hardware addresses, a relay that re-frames other
// hosts' packets, or a NIC randomising its MAC. Each sighting then looked like
// another new neighbour, and a single address could grow twenty inventory
// rows and twenty "new device" alerts in an afternoon. Past this many, the
// address has demonstrated that its link-layer address means nothing, and
// further sightings stop creating entries. Devices already on record keep
// updating.
const MaxMACsPerAddress = 4

// UpsertDevice records or refreshes a LAN device by MAC. It returns whether
// the device was newly created, which the new-device detector uses to decide
// whether to raise an alert. First-seen time is preserved across updates.
//
// The address is filed by family, so a dual-stack device keeps both without
// either overwriting the other, and a link-local IPv6 address never displaces
// a routable one.
//
// The insert-or-update runs in one transaction with an explicit existence
// check so "is new" is correct even under a fixed clock (where comparing
// timestamps would not tell an insert from an update).
func (s *Store) UpsertDevice(ctx context.Context, mac, ip, hostname, vendor string) (isNew bool, err error) {
	addr, _ := netip.ParseAddr(ip)
	addr = addr.Unmap()
	col := "ip"
	if addr.IsValid() && addr.Is6() {
		col = "ip6"
	}
	text := ""
	if addr.IsValid() {
		text = addr.String()
	}

	now := toMs(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur6 string
	err = tx.QueryRowContext(ctx, `SELECT ip6 FROM devices WHERE mac = ?`, mac).Scan(&cur6)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	if exists {
		// A link-local address is real but useless as an identifier: every
		// interface has one and it says nothing about the network. Keep it
		// only until something routable turns up.
		if col == "ip6" && linkLocal(addr) && cur6 != "" && !linkLocalText(cur6) {
			text = cur6
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE devices SET
				`+col+`  = CASE WHEN ? != '' THEN ? ELSE `+col+` END,
				hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
				vendor   = CASE WHEN ? != '' THEN ? ELSE vendor END,
				last_seen_ms = ?
			WHERE mac = ?`,
			text, text, hostname, hostname, vendor, vendor, now, mac); err != nil {
			return false, err
		}
	} else {
		if text != "" {
			var claimed int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM devices WHERE `+col+` = ?`, text).Scan(&claimed); err != nil {
				return false, err
			}
			if claimed >= MaxMACsPerAddress {
				return false, nil
			}
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devices (mac, `+col+`, hostname, vendor, first_seen_ms, last_seen_ms)
			VALUES (?,?,?,?,?,?)`,
			mac, text, hostname, vendor, now, now); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return !exists, nil
}

func linkLocal(a netip.Addr) bool { return a.IsValid() && a.IsLinkLocalUnicast() }

func linkLocalText(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.IsLinkLocalUnicast()
}

// ListDevices returns known devices, most recently seen first.
func (s *Store) ListDevices(ctx context.Context) ([]model.Device, error) {
	return s.queryDevices(ctx, `ORDER BY last_seen_ms DESC`)
}

// ForgetDevices removes inventory entries by MAC and reports how many rows
// went. Discovery is passive, so a device that is still on the network comes
// back on its next packet: this clears out entries that never described a
// device, not the device itself.
func (s *Store) ForgetDevices(ctx context.Context, macs []string) (int64, error) {
	if len(macs) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var total int64
	for _, mac := range macs {
		res, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE mac = ?`, mac)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// WatchedDevices returns devices with presence tracking enabled.
func (s *Store) WatchedDevices(ctx context.Context) ([]model.Device, error) {
	return s.queryDevices(ctx, `WHERE watch_presence = 1 ORDER BY last_seen_ms DESC`)
}

func (s *Store) queryDevices(ctx context.Context, tail string) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, mac, ip, ip6, label, hostname, vendor, watch_presence, present, policy, first_seen_ms, last_seen_ms
		FROM devices `+tail)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Device
	for rows.Next() {
		var d model.Device
		var ip, ip6 string
		var watch, present int
		var policy string
		var first, last int64
		if err := rows.Scan(&d.ID, &d.MAC, &ip, &ip6, &d.Label, &d.Hostname, &d.Vendor, &watch, &present, &policy, &first, &last); err != nil {
			return nil, err
		}
		d.Policy = model.DevicePolicy(policy)
		d.IP, _ = netip.ParseAddr(ip)
		d.IP6, _ = netip.ParseAddr(ip6)
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
		WHERE (ip != '' AND ip = ?) OR (ip6 != '' AND ip6 = ?)
		ORDER BY last_seen_ms DESC LIMIT 1`, ip, ip).Scan(&label, &hostname)
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

// SetDevicePolicy assigns a per-device network policy (empty clears it).
func (s *Store) SetDevicePolicy(ctx context.Context, mac string, policy model.DevicePolicy) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET policy = ? WHERE mac = ?`, string(policy), mac)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDeviceNotFound
	}
	return nil
}

// RestrictedDevices returns every device carrying a policy, so the firewall
// can translate them into kernel rules.
func (s *Store) RestrictedDevices(ctx context.Context) ([]model.Device, error) {
	return s.queryDevices(ctx, `WHERE policy != '' ORDER BY ip`)
}
