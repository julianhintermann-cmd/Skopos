package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Backup writes a consistent copy of the database to dir using SQLite's
// VACUUM INTO, which produces a defragmented, self-contained snapshot without
// blocking writers for long. The file is named skopos-YYYYMMDD-HHMMSS.db.
// Old generations beyond keep are pruned.
//
// dir is expected to live on cold storage; a temporary unavailability is
// reported as an error so the scheduler can retry and notify, but it never
// affects the live database.
func (s *Store) Backup(ctx context.Context, dir string, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("backup: preparing dir: %w", err)
	}
	name := fmt.Sprintf("skopos-%s.db", s.now().UTC().Format("20060102-150405"))
	dest := filepath.Join(dir, name)

	// VACUUM INTO takes a read lock only; it cannot run inside a transaction.
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, dest); err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	if err := pruneBackups(dir, keep); err != nil {
		return dest, fmt.Errorf("backup written but pruning failed: %w", err)
	}
	return dest, nil
}

// pruneBackups keeps the newest `keep` backup files and removes older ones.
func pruneBackups(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "skopos-") && strings.HasSuffix(e.Name(), ".db") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	// Timestamped names sort chronologically as strings.
	sort.Strings(names)
	for _, old := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, old)); err != nil {
			return err
		}
	}
	return nil
}

// CheckpointFor is exposed so callers can force a WAL checkpoint (e.g. before
// measuring size in tests or after large deletes).
func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// timeFromBackupName parses the timestamp encoded in a backup file name.
// Unparseable names sort last. Currently used only by tests.
func timeFromBackupName(name string) (time.Time, bool) {
	base := strings.TrimSuffix(strings.TrimPrefix(name, "skopos-"), ".db")
	t, err := time.Parse("20060102-150405", base)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
