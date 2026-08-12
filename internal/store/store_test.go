package store

import (
	"path/filepath"
	"testing"
	"time"
)

// testStore opens a Store backed by a temp-file database with a fixed clock.
func testStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	s, err := Open(Options{
		Path:  filepath.Join(t.TempDir(), "skopos.db"),
		Clock: func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, base
}

func TestOpenRunsMigrations(t *testing.T) {
	s, _ := testStore(t)

	var version int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	want, err := SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != want {
		t.Errorf("applied version = %d, want %d", version, want)
	}
	if want < 1 {
		t.Error("expected at least one migration")
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skopos.db")

	s1, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = s1.Close()

	// Re-opening must not re-apply migrations or error.
	s2, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s2.Close()

	var count int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	want, _ := SchemaVersion()
	if count != want {
		t.Errorf("schema_migrations rows = %d, want %d (idempotent apply)", count, want)
	}
}

func TestWALEnabled(t *testing.T) {
	s, _ := testStore(t)
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestLoadMigrationsContiguous(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for i, m := range ms {
		if m.version != i+1 {
			t.Errorf("migration %d has version %d, want %d", i, m.version, i+1)
		}
	}
}
