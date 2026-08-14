package store

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestApplyRetentionDropsOldRawFlowsKeepsRollups(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	old := base.Add(-10 * 24 * time.Hour) // 10 days ago
	recent := base.Add(-1 * time.Hour)
	if err := s.WriteFlows([]model.Flow{
		mkFlow(old, "192.168.1.10", "9.9.9.9", 443, 1000),
		mkFlow(recent, "192.168.1.10", "9.9.9.9", 443, 1000),
	}); err != nil {
		t.Fatal(err)
	}

	// Keep raw flows 7 days; keep all rollups forever.
	deleted, err := s.ApplyRetention(ctx, RetentionPolicy{RawFlows: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("ApplyRetention: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (the 10-day-old flow)", deleted)
	}

	n, _ := s.CountFlows(ctx)
	if n != 1 {
		t.Errorf("remaining raw flows = %d, want 1", n)
	}

	// Rollups must be untouched: the old flow's daily bucket still exists.
	var rollupRows int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM rollup_1d`).Scan(&rollupRows)
	if rollupRows != 2 {
		t.Errorf("rollup_1d rows = %d, want 2 (retention must not touch rollups)", rollupRows)
	}
}

func TestDeleteOldestFlowsIsOrdered(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	var flows []model.Flow
	for i := 0; i < 100; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		flows = append(flows, mkFlow(ts, "192.168.1.10", "9.9.9.9", 443, 1000))
	}
	if err := s.WriteFlows(flows); err != nil {
		t.Fatal(err)
	}

	// Deleting the oldest 40 must leave the 60 newest, starting at base+40s.
	n, err := s.deleteOldestFlows(ctx, 40)
	if err != nil {
		t.Fatalf("deleteOldestFlows: %v", err)
	}
	if n != 40 {
		t.Fatalf("deleted %d, want 40", n)
	}
	var oldestRemaining int64
	if err := s.db.QueryRow(`SELECT MIN(start_ms) FROM flows`).Scan(&oldestRemaining); err != nil {
		t.Fatal(err)
	}
	if want := toMs(base.Add(40 * time.Second)); oldestRemaining != want {
		t.Errorf("oldest remaining = %d, want %d (oldest-first deletion)", oldestRemaining, want)
	}
}

func TestEnforceHotLimitReducesSizeAndTerminates(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	var flows []model.Flow
	for i := 0; i < 20000; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		src := netip.AddrFrom4([4]byte{10, 0, byte(i / 250), byte(i % 250)}).String()
		flows = append(flows, mkFlow(ts, src, "9.9.9.9", 443, 1000))
	}
	if err := s.WriteFlows(flows); err != nil {
		t.Fatal(err)
	}
	_ = s.Checkpoint(ctx)

	before, err := s.diskSize()
	if err != nil {
		t.Fatal(err)
	}
	cap := before / 2

	// The rollups this fixture builds outlast the raw flows, so draining
	// every flow still leaves the file over a half-size cap. That is the
	// documented behaviour — rollups are kept on purpose — and it now reports
	// itself instead of returning as if the cap had been met.
	deleted, err := s.EnforceHotLimit(ctx, cap)
	if err != nil && !errors.Is(err, ErrHotLimitUnreachable) {
		t.Fatalf("EnforceHotLimit: %v", err)
	}
	if deleted == 0 {
		t.Fatal("expected flows to be deleted to get under the cap")
	}

	after, err := s.diskSize()
	if err != nil {
		t.Fatal(err)
	}
	remaining, _ := s.CountFlows(ctx)
	// Either we are under the cap, or we dropped every raw flow trying
	// (rollups are preserved by design and may hold size above the cap).
	if after > cap && remaining > 0 {
		t.Errorf("after=%d still over cap=%d with %d raw flows remaining", after, cap, remaining)
	}
}

func TestBackupCreatesFileAndPrunes(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	// Advance the clock between backups so file names differ.
	base := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		at := base.Add(time.Duration(i) * time.Hour)
		s.clock = func() time.Time { return at }
		if _, err := s.Backup(ctx, dir, 2); err != nil {
			t.Fatalf("Backup %d: %v", i, err)
		}
	}

	entries, _ := os.ReadDir(dir)
	var backups []string
	for _, e := range entries {
		if _, ok := timeFromBackupName(e.Name()); ok {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) != 2 {
		t.Errorf("kept %d backups, want 2", len(backups))
	}

	// Kept backups must be openable databases.
	for _, b := range backups {
		s2, err := Open(Options{Path: filepath.Join(dir, b)})
		if err != nil {
			t.Errorf("backup %s not openable: %v", b, err)
			continue
		}
		if err := s2.Close(); err != nil {
			t.Errorf("closing backup %s: %v", b, err)
		}
	}
}
