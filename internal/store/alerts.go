package store

import (
	"context"
	"database/sql"
	"net/netip"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// InsertAlert stores an alert and returns it with its assigned ID.
func (s *Store) InsertAlert(ctx context.Context, a model.Alert) (model.Alert, error) {
	if a.Time.IsZero() {
		a.Time = s.now()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (time_ms, detector, severity, source, title, detail, count, ack)
		VALUES (?,?,?,?,?,?,?,0)`,
		toMs(a.Time), a.Detector, string(a.Severity), addrString(a.Source),
		a.Title, a.Detail, a.Count)
	if err != nil {
		return model.Alert{}, err
	}
	id, _ := res.LastInsertId()
	a.ID = id
	return a, nil
}

// AlertFilter narrows a ListAlerts query.
type AlertFilter struct {
	// UnackedOnly returns only alerts that have not been acknowledged.
	UnackedOnly bool
	// Limit caps the number of rows (0 = a sensible default).
	Limit int
}

// ListAlerts returns alerts most recent first.
func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]model.Alert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, time_ms, detector, severity, source, title, detail, count, ack, ack_ms
	      FROM alerts`
	if f.UnackedOnly {
		q += ` WHERE ack = 0`
	}
	q += ` ORDER BY time_ms DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckAlert marks an alert acknowledged.
func (s *Store) AckAlert(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET ack = 1, ack_ms = ? WHERE id = ?`,
		toMs(s.now()), id)
	return err
}

// CountUnackedAlerts returns how many alerts are unacknowledged.
func (s *Store) CountUnackedAlerts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE ack = 0`).Scan(&n)
	return n, err
}

func scanAlert(rows *sql.Rows) (model.Alert, error) {
	var a model.Alert
	var sourceStr, sev string
	var ackMs sql.NullInt64
	var timeMs int64
	if err := rows.Scan(&a.ID, &timeMs, &a.Detector, &sev, &sourceStr,
		&a.Title, &a.Detail, &a.Count, &a.Ack, &ackMs); err != nil {
		return model.Alert{}, err
	}
	a.Time = fromMs(timeMs)
	a.Severity = model.Severity(sev)
	if sourceStr != "" {
		a.Source, _ = netip.ParseAddr(sourceStr)
	}
	if ackMs.Valid {
		t := fromMs(ackMs.Int64)
		a.AckTime = &t
	}
	return a, nil
}

// addrString renders an address, or "" when it is the zero value.
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
