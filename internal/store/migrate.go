package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads and orders the embedded migration files. File names
// must be "NNNN_description.sql"; NNNN is the ascending version number.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		numStr, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q must be named NNNN_description.sql", e.Name())
		}
		n, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, fmt.Errorf("migration %q has non-numeric version: %w", e.Name(), err)
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+e.Name())
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: n, name: e.Name(), sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 1; got %d at position %d", m.version, i+1)
		}
	}
	return ms, nil
}

// SchemaVersion returns the highest migration version defined in the binary.
func SchemaVersion() (int, error) {
	ms, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	if len(ms) == 0 {
		return 0, nil
	}
	return ms[len(ms)-1].version, nil
}

// migrate applies all pending migrations inside individual transactions and
// records them in schema_migrations. It is safe to call on every startup.
func migrate(db *sql.DB) (applied int, err error) {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name    TEXT NOT NULL,
		applied_ms INTEGER NOT NULL
	)`); err != nil {
		return 0, fmt.Errorf("creating schema_migrations: %w", err)
	}

	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}

	ms, err := loadMigrations()
	if err != nil {
		return 0, err
	}

	// A database newer than this binary means someone rolled the image back
	// over a schema it does not know. Today's migrations are additive enough
	// to survive that, but a future one that drops or renames a column would
	// not be, and starting up cheerfully against a schema from the future is
	// how a rollback turns into data loss. Refuse, and say which versions are
	// involved so the operator can pick the right image or restore a backup.
	if len(ms) > 0 && current > ms[len(ms)-1].version {
		return 0, fmt.Errorf(
			"database schema is version %d but this build only knows %d: it was written by a newer Skopos. "+
				"Run the newer version, or restore a backup taken before the upgrade",
			current, ms[len(ms)-1].version)
	}

	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := applyOne(db, m); err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.name, err)
		}
		applied++
	}
	return applied, nil
}

func applyOne(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(m.sql); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, name, applied_ms) VALUES (?, ?, ?)`,
		m.version, m.name, nowMs(),
	); err != nil {
		return err
	}
	return tx.Commit()
}
