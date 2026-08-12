package store

import (
	"context"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Audit appends an entry to the tamper-evident action log. Every block,
// unblock, login and configuration-affecting action goes through here.
func (s *Store) Audit(ctx context.Context, e model.AuditEntry) error {
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit (time_ms, actor, action, target, detail)
		VALUES (?,?,?,?,?)`,
		toMs(e.Time), e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// ListAudit returns audit entries most recent first, up to limit.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, time_ms, actor, action, target, detail
		FROM audit ORDER BY time_ms DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ms int64
		if err := rows.Scan(&e.ID, &ms, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = fromMs(ms)
		out = append(out, e)
	}
	return out, rows.Err()
}
