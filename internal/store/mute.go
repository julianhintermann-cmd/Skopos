package store

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// MuteRule suppresses matching alerts. Every criterion is optional and they
// combine with AND: an empty rule would mute everything, so the constructor
// refuses one. This is the operator's answer to "stop telling me about this"
// — a filter on notification, never on recording: muted findings still count
// toward blocks and still show in the flow history.
type MuteRule struct {
	ID       int64      `json:"id"`
	Detector string     `json:"detector,omitempty"`
	Prefix   string     `json:"prefix,omitempty"`
	Port     int        `json:"port,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
}

// Matches reports whether the rule covers a finding.
func (m MuteRule) Matches(detector string, source netip.Addr, port int, now time.Time) bool {
	if m.Expires != nil && now.After(*m.Expires) {
		return false
	}
	if m.Detector != "" && m.Detector != detector {
		return false
	}
	if m.Port != 0 && m.Port != port {
		return false
	}
	if m.Prefix != "" {
		p, err := netip.ParsePrefix(m.Prefix)
		if err != nil || !p.Contains(source.Unmap()) {
			return false
		}
	}
	return true
}

// AddMuteRule validates and stores a rule.
func (s *Store) AddMuteRule(ctx context.Context, r MuteRule) (MuteRule, error) {
	if r.Detector == "" && r.Prefix == "" && r.Port == 0 {
		return r, fmt.Errorf("store: a mute rule needs at least one criterion")
	}
	if r.Prefix != "" {
		if _, err := netip.ParsePrefix(r.Prefix); err != nil {
			return r, fmt.Errorf("store: mute prefix %q: %w", r.Prefix, err)
		}
	}
	if r.Port < 0 || r.Port > 65535 {
		return r, fmt.Errorf("store: mute port out of range")
	}
	if r.Created.IsZero() {
		r.Created = s.now()
	}
	var expires any
	if r.Expires != nil {
		expires = toMs(*r.Expires)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO mute_rules (detector, prefix, port, reason, created_ms, expires_ms)
		VALUES (?,?,?,?,?,?)`,
		r.Detector, r.Prefix, r.Port, r.Reason, toMs(r.Created), expires)
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, nil
}

// ListMuteRules returns every rule, newest first.
func (s *Store) ListMuteRules(ctx context.Context) ([]MuteRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, detector, prefix, port, reason, created_ms, expires_ms
		FROM mute_rules ORDER BY created_ms DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []MuteRule
	for rows.Next() {
		var (
			r       MuteRule
			created int64
			expires *int64
		)
		if err := rows.Scan(&r.ID, &r.Detector, &r.Prefix, &r.Port, &r.Reason, &created, &expires); err != nil {
			return nil, err
		}
		r.Created = fromMs(created)
		if expires != nil {
			t := fromMs(*expires)
			r.Expires = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteMuteRule removes a rule, reporting whether it existed.
func (s *Store) DeleteMuteRule(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mute_rules WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
