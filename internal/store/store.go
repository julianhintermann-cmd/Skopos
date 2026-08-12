// Package store is Skopos' persistence layer: a single embedded SQLite
// database (WAL mode) on hot storage holding flows, rollups, alerts, blocks,
// devices and the audit log. Schema changes ship as embedded, versioned
// migrations applied automatically at startup.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Clock supplies the current time; tests substitute a deterministic one.
type Clock func() time.Time

// Store wraps the database connection and its configuration.
type Store struct {
	db    *sql.DB
	path  string
	clock Clock
}

// Options configures a Store.
type Options struct {
	// Path is the SQLite database file on hot storage.
	Path string
	// Clock overrides the time source (defaults to time.Now).
	Clock Clock
}

// pragmas make SQLite suitable for a concurrent read / single-writer service:
// WAL for read-during-write, NORMAL sync for durability at WAL speed, a busy
// timeout so brief writer contention waits instead of erroring, and foreign
// keys on.
// auto_vacuum = INCREMENTAL is set before any table exists so the hot-limit
// enforcer can hand freed pages back to the filesystem with
// PRAGMA incremental_vacuum instead of a full, locking VACUUM.
const pragmas = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;
PRAGMA auto_vacuum = INCREMENTAL;
`

// Open opens (creating if needed) the database, applies pragmas and runs
// pending migrations.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("store: path is required")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o755); err != nil {
		return nil, fmt.Errorf("store: creating data dir: %w", err)
	}

	db, err := sql.Open("sqlite", opts.Path)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	// SQLite is a single-writer engine; one connection avoids "database is
	// locked" churn under WAL and keeps busy_timeout meaningful.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(pragmas); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: applying pragmas: %w", err)
	}

	s := &Store{db: db, path: opts.Path, clock: opts.Clock}

	if _, err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrating: %w", err)
	}
	return s, nil
}

// DB exposes the underlying handle for packages in this module that need
// direct query access (e.g. the API read paths).
func (s *Store) DB() *sql.DB { return s.db }

// now returns the store's current time.
func (s *Store) now() time.Time { return s.clock() }

// Close flushes WAL back into the main database file and closes the handle.
func (s *Store) Close() error {
	// A checkpoint on shutdown keeps the -wal file from growing unbounded
	// across restarts and leaves the main file self-contained for backups.
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return s.db.Close()
}

func nowMs() int64 { return time.Now().UnixMilli() }

func toMs(t time.Time) int64 { return t.UnixMilli() }

func fromMs(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
