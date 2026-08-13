package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// incidentGap is how long a source must stay quiet before its next alert
// starts a new incident rather than extending the current one. Long enough
// that a scan pausing to retry stays one episode, short enough that today's
// visit is not merged with last week's.
const incidentGap = 2 * time.Hour

// Incident groups the alerts of one source into a single episode, so the
// Alerts view can say "one attacker, 40 events" instead of listing 40 rows.
type Incident struct {
	ID         int64         `json:"id"`
	Source     string        `json:"source"`
	First      time.Time     `json:"first_seen"`
	Last       time.Time     `json:"last_seen"`
	Severity   string        `json:"severity"`
	Detectors  []string      `json:"detectors"`
	AlertCount int64         `json:"alert_count"`
	Title      string        `json:"title"`
	Ack        bool          `json:"ack"`
	Alerts     []model.Alert `json:"alerts,omitempty"`
}

// AttachToIncident files an alert into the source's open incident, starting
// one when the source has been quiet. Returns the incident's ID.
func (s *Store) AttachToIncident(ctx context.Context, a model.Alert) (int64, error) {
	if !a.Source.IsValid() {
		return 0, nil
	}
	src := a.Source.String()
	cutoff := toMs(a.Time.Add(-incidentGap))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id        int64
		severity  string
		detectors string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT id, severity, detectors FROM incidents
		WHERE source = ? AND last_ms >= ?
		ORDER BY last_ms DESC LIMIT 1`, src, cutoff).Scan(&id, &severity, &detectors)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `
			INSERT INTO incidents (source, first_ms, last_ms, severity, detectors, alert_count, title, ack)
			VALUES (?,?,?,?,?,?,?,0)`,
			src, toMs(a.Time), toMs(a.Time), string(a.Severity), a.Detector, a.Count, a.Title)
		if err != nil {
			return 0, err
		}
		id, _ = res.LastInsertId()
	case err != nil:
		return 0, err
	default:
		// Extend: the incident keeps the highest severity seen and the union
		// of detectors, and a new alert re-opens it for acknowledgement.
		merged := mergeDetectors(detectors, a.Detector)
		if model.Severity(a.Severity).Rank() > model.Severity(severity).Rank() {
			severity = string(a.Severity)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE incidents
			SET last_ms = ?, severity = ?, detectors = ?, alert_count = alert_count + ?,
			    title = ?, ack = 0
			WHERE id = ?`,
			toMs(a.Time), severity, merged, a.Count, a.Title, id); err != nil {
			return 0, err
		}
	}

	if a.ID > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE alerts SET incident_id = ? WHERE id = ?`, id, a.ID); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// mergeDetectors adds one detector to a comma-separated list, keeping it
// sorted and unique.
func mergeDetectors(list, add string) string {
	seen := map[string]bool{}
	for _, d := range strings.Split(list, ",") {
		if d = strings.TrimSpace(d); d != "" {
			seen[d] = true
		}
	}
	if add != "" {
		seen[add] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// IncidentFilter narrows a listing.
type IncidentFilter struct {
	UnackedOnly bool
	Limit       int
}

// ListIncidents returns incidents newest activity first.
func (s *Store) ListIncidents(ctx context.Context, f IncidentFilter) ([]Incident, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	query := `SELECT id, source, first_ms, last_ms, severity, detectors, alert_count, title, ack
		FROM incidents`
	if f.UnackedOnly {
		query += ` WHERE ack = 0`
	}
	query += ` ORDER BY last_ms DESC LIMIT ?`

	rows, err := s.db.QueryContext(ctx, query, f.Limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Incident
	for rows.Next() {
		var (
			in          Incident
			first, last int64
			detectors   string
			ack         int
		)
		if err := rows.Scan(&in.ID, &in.Source, &first, &last, &in.Severity,
			&detectors, &in.AlertCount, &in.Title, &ack); err != nil {
			return nil, err
		}
		in.First, in.Last = fromMs(first), fromMs(last)
		in.Ack = ack != 0
		if detectors != "" {
			in.Detectors = strings.Split(detectors, ",")
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// IncidentByID returns one incident with its alerts, newest first.
func (s *Store) IncidentByID(ctx context.Context, id int64) (Incident, error) {
	list, err := s.ListIncidents(ctx, IncidentFilter{Limit: 500})
	if err != nil {
		return Incident{}, err
	}
	var found *Incident
	for i := range list {
		if list[i].ID == id {
			found = &list[i]
			break
		}
	}
	if found == nil {
		return Incident{}, sql.ErrNoRows
	}
	alerts, err := s.alertsOfIncident(ctx, id)
	if err != nil {
		return *found, err
	}
	found.Alerts = alerts
	return *found, nil
}

func (s *Store) alertsOfIncident(ctx context.Context, id int64) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, time_ms, detector, severity, source, title, detail, count, ack, ack_ms
		FROM alerts WHERE incident_id = ? ORDER BY time_ms DESC LIMIT 200`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []model.Alert
	for rows.Next() {
		var (
			a       model.Alert
			ts      int64
			src     string
			ack     int
			ackTime sql.NullInt64
		)
		if err := rows.Scan(&a.ID, &ts, &a.Detector, &a.Severity, &src,
			&a.Title, &a.Detail, &a.Count, &ack, &ackTime); err != nil {
			return nil, err
		}
		a.Time = fromMs(ts)
		a.Source, _ = netip.ParseAddr(src)
		a.Ack = ack != 0
		if ackTime.Valid {
			t := fromMs(ackTime.Int64)
			a.AckTime = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckIncident acknowledges an incident and every alert inside it.
func (s *Store) AckIncident(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := toMs(s.now())
	if _, err := tx.ExecContext(ctx, `UPDATE incidents SET ack = 1 WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE alerts SET ack = 1, ack_ms = ? WHERE incident_id = ? AND ack = 0`, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PruneIncidents drops incidents whose last activity predates the cutoff.
func (s *Store) PruneIncidents(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM incidents WHERE last_ms < ?`, toMs(before))
	return err
}
