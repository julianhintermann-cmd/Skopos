package store

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// AddBlock records an active block for a prefix. If an active block already
// exists for the same prefix it is updated (origin, reason, expiry refreshed)
// rather than duplicated. Returns the stored block.
func (s *Store) AddBlock(ctx context.Context, b model.Block) (model.Block, error) {
	now := s.now()
	if b.Created.IsZero() {
		b.Created = now
	}
	b.Active = true

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Block{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var existingID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM blocks WHERE prefix = ? AND active = 1`, b.Prefix.String()).Scan(&existingID)
	switch err {
	case nil:
		if _, err := tx.ExecContext(ctx, `
			UPDATE blocks SET origin=?, reason=?, expires_ms=? WHERE id=?`,
			string(b.Origin), b.Reason, nullableMs(b.Expires), existingID); err != nil {
			return model.Block{}, err
		}
		b.ID = existingID
	case sql.ErrNoRows:
		res, err := tx.ExecContext(ctx, `
			INSERT INTO blocks (prefix, origin, reason, created_ms, expires_ms, active)
			VALUES (?,?,?,?,?,1)`,
			b.Prefix.String(), string(b.Origin), b.Reason, toMs(b.Created), nullableMs(b.Expires))
		if err != nil {
			return model.Block{}, err
		}
		b.ID, _ = res.LastInsertId()
	default:
		return model.Block{}, err
	}

	if err := tx.Commit(); err != nil {
		return model.Block{}, err
	}
	return b, nil
}

// RemoveBlock deactivates the active block for a prefix, recording when it was
// removed. Returns whether a block was actually removed.
func (s *Store) RemoveBlock(ctx context.Context, prefix netip.Prefix) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE blocks SET active = 0, removed_ms = ? WHERE prefix = ? AND active = 1`,
		toMs(s.now()), prefix.String())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ActiveBlocks returns all currently-active blocks. This is the desired state
// the firewall reconciler drives the kernel toward.
func (s *Store) ActiveBlocks(ctx context.Context) ([]model.Block, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, prefix, origin, reason, created_ms, expires_ms, active, removed_ms
		FROM blocks WHERE active = 1 ORDER BY created_ms DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Block
	for rows.Next() {
		b, err := scanBlock(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ExpireBlocks deactivates active blocks whose TTL has passed and returns
// them, so the caller can remove them from the kernel and audit the expiry.
func (s *Store) ExpireBlocks(ctx context.Context) ([]model.Block, error) {
	now := s.now()
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, prefix, origin, reason, created_ms, expires_ms, active, removed_ms
		FROM blocks WHERE active = 1 AND expires_ms IS NOT NULL AND expires_ms <= ?`,
		toMs(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var expired []model.Block
	for rows.Next() {
		b, err := scanBlock(rows)
		if err != nil {
			return nil, err
		}
		expired = append(expired, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, b := range expired {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE blocks SET active = 0, removed_ms = ? WHERE id = ?`, toMs(now), b.ID); err != nil {
			return expired, err
		}
	}
	return expired, nil
}

func scanBlock(rows *sql.Rows) (model.Block, error) {
	var b model.Block
	var prefix, origin string
	var created int64
	var expires, removed sql.NullInt64
	if err := rows.Scan(&b.ID, &prefix, &origin, &b.Reason, &created, &expires, &b.Active, &removed); err != nil {
		return model.Block{}, err
	}
	b.Prefix, _ = netip.ParsePrefix(prefix)
	b.Origin = model.BlockOrigin(origin)
	b.Created = fromMs(created)
	if expires.Valid {
		t := fromMs(expires.Int64)
		b.Expires = &t
	}
	if removed.Valid {
		t := fromMs(removed.Int64)
		b.RemovedAt = &t
	}
	return b, nil
}

// nullableMs renders a *time.Time as Unix ms or SQL NULL.
func nullableMs(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}
