package store

import (
	"context"
	"database/sql"
	"errors"
)

// GetMeta reads a singleton key/value entry. The bool reports presence.
func (s *Store) GetMeta(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(context.Background(),
		`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetMeta upserts a singleton key/value entry.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
