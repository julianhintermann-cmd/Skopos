package store

import (
	"context"
	"errors"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// ErrZoneNotFound is returned when a Cloudflare zone id is unknown.
var ErrZoneNotFound = errors.New("cloudflare zone not found")

// cfTokenKey holds the AES-GCM-sealed Cloudflare API token in the meta table.
// The plaintext token never touches disk or the config file.
const cfTokenKey = "cloudflare_token"

// CFSetToken stores the sealed token (opaque ciphertext).
func (s *Store) CFSetToken(sealed string) error { return s.SetMeta(cfTokenKey, sealed) }

// CFToken returns the sealed token and whether one is set.
func (s *Store) CFToken() (string, bool, error) { return s.GetMeta(cfTokenKey) }

// CFDeleteToken removes the sealed token.
func (s *Store) CFDeleteToken(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, cfTokenKey)
	return err
}

// CFUpsertZone inserts or refreshes a zone, preserving the operator's
// monitored flag on an existing row (auto-refresh must not silently re-enable
// a zone the operator turned off).
func (s *Store) CFUpsertZone(ctx context.Context, z model.CFZone) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cf_zones (id, name, status, monitored, added_ms)
		VALUES (?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name   = excluded.name,
			status = excluded.status`,
		z.ID, z.Name, z.Status, boolToInt(z.Monitored), toMs(s.now()))
	return err
}

// CFListZones returns connected zones, alphabetically by name.
func (s *Store) CFListZones(ctx context.Context) ([]model.CFZone, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, status, monitored, added_ms
		FROM cf_zones ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.CFZone
	for rows.Next() {
		var z model.CFZone
		var monitored int
		var added int64
		if err := rows.Scan(&z.ID, &z.Name, &z.Status, &monitored, &added); err != nil {
			return nil, err
		}
		z.Monitored = monitored != 0
		z.Added = fromMs(added)
		out = append(out, z)
	}
	return out, rows.Err()
}

// CFSetZoneMonitored toggles whether a zone's traffic is monitored.
func (s *Store) CFSetZoneMonitored(ctx context.Context, id string, monitored bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE cf_zones SET monitored = ? WHERE id = ?`, boolToInt(monitored), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrZoneNotFound
	}
	return nil
}

// CFPruneZonesExcept removes zones whose ids are not in keep — used after a
// refresh so zones the token can no longer see disappear. An empty keep set
// clears the table (used on disconnect).
func (s *Store) CFPruneZonesExcept(ctx context.Context, keep map[string]bool) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM cf_zones`)
	if err != nil {
		return err
	}
	var toDelete []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		if !keep[id] {
			toDelete = append(toDelete, id)
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range toDelete {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM cf_zones WHERE id = ?`, id); err != nil {
			return err
		}
	}
	return nil
}

// CFClearZones removes every connected zone.
func (s *Store) CFClearZones(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cf_zones`)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
