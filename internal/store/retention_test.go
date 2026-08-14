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

// alertAt inserts one alert and files it into its source's incident, the way
// the policy engine does.
func alertAt(t *testing.T, s *Store, ts time.Time, src string) model.Alert {
	t.Helper()
	a, err := s.InsertAlert(context.Background(), model.Alert{
		Time:     ts,
		Detector: "portscan",
		Severity: model.SeverityWarning,
		Source:   netip.MustParseAddr(src),
		Title:    "port scan",
		Count:    1,
	})
	if err != nil {
		t.Fatalf("InsertAlert: %v", err)
	}
	if _, err := s.AttachToIncident(context.Background(), a); err != nil {
		t.Fatalf("AttachToIncident: %v", err)
	}
	return a
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

func TestPruneAlertsDropsOldAlertsAndTheEpisodesTheyEmptied(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()
	cutoff := base.Add(-365 * 24 * time.Hour)

	// A finished episode from before the cutoff: both it and its alert go.
	alertAt(t, s, cutoff.Add(-30*24*time.Hour), "203.0.113.7")
	// A recent episode: untouched.
	alertAt(t, s, base.Add(-time.Hour), "198.51.100.4")
	// An episode straddling the cutoff — two alerts from one source an hour
	// apart, so they group. The older alert goes, the episode stays because
	// it still has the newer one.
	alertAt(t, s, cutoff.Add(-30*time.Minute), "192.0.2.9")
	alertAt(t, s, cutoff.Add(30*time.Minute), "192.0.2.9")

	if got := countRows(t, s, "incidents"); got != 3 {
		t.Fatalf("fixture built %d incidents, want 3", got)
	}

	deleted, err := s.PruneAlerts(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneAlerts: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2 (both alerts older than the cutoff)", deleted)
	}
	if got := countRows(t, s, "alerts"); got != 2 {
		t.Errorf("remaining alerts = %d, want 2", got)
	}
	// The emptied episode must go with its alerts: an incident whose events
	// have all been deleted is a claim the Alerts view cannot back up.
	if got := countRows(t, s, "incidents"); got != 2 {
		t.Errorf("remaining incidents = %d, want 2 (the fully expired one is gone)", got)
	}
	inc, err := s.ListIncidents(ctx, IncidentFilter{})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	for _, i := range inc {
		if i.Source == "203.0.113.7" {
			t.Errorf("the expired episode survived its alerts: %+v", i)
		}
		full, err := s.IncidentByID(ctx, i.ID)
		if err != nil {
			t.Fatalf("IncidentByID(%d): %v", i.ID, err)
		}
		if len(full.Alerts) == 0 {
			t.Errorf("incident %d (%s) is left with no alerts", i.ID, i.Source)
		}
	}
}

func TestPruneAlertsKeepsEverythingWhenRetentionIsOff(t *testing.T) {
	// "0" means keep forever, and a zero cutoff must delete nothing however
	// old the history is.
	s, base := testStore(t)
	alertAt(t, s, base.Add(-10*365*24*time.Hour), "203.0.113.7")

	deleted, err := s.PruneAlerts(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("PruneAlerts: %v", err)
	}
	if deleted != 0 || countRows(t, s, "alerts") != 1 {
		t.Errorf("deleted = %d with %d alerts left, want 0 and 1", deleted, countRows(t, s, "alerts"))
	}
}
