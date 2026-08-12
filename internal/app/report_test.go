package app

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func TestNextWeekly(t *testing.T) {
	// Wednesday noon → next Sunday 18:00.
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC) // a Wednesday
	next := nextWeekly(now, time.Sunday, 18)
	if next.Weekday() != time.Sunday || next.Hour() != 18 || !next.After(now) {
		t.Fatalf("next = %v", next)
	}
	// Sunday 19:00 → the following Sunday, not today.
	now = time.Date(2026, 8, 16, 19, 0, 0, 0, time.UTC) // a Sunday
	next = nextWeekly(now, time.Sunday, 18)
	if next.Sub(now) < 6*24*time.Hour {
		t.Fatalf("must roll to next week, got %v", next)
	}
}

func TestBuildWeeklyReport(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	now := time.Now()
	_ = st.WriteFlows([]model.Flow{{
		Start: now.Add(-2 * time.Hour), End: now.Add(-2 * time.Hour),
		SrcIP: netip.MustParseAddr("192.168.1.9"), DstIP: netip.MustParseAddr("1.1.1.1"),
		Proto: model.ProtoTCP, Dir: model.DirLANtoWAN, OutBytes: 5 << 20,
	}})
	if _, err := st.UpsertDevice(ctx, "aa:bb:cc:dd:ee:09", "192.168.1.9", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceLabel(ctx, "aa:bb:cc:dd:ee:09", "NAS"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAlert(ctx, model.Alert{Detector: "portscan", Severity: model.SeverityWarning, Title: "scan", Count: 3}); err != nil {
		t.Fatal(err)
	}

	app := &App{log: slog.New(slog.NewTextHandler(os.Stderr, nil)), clock: time.Now}
	title, body, err := app.buildWeeklyReport(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if title == "" || !strings.Contains(body, "Traffic: 5.0 MiB") {
		t.Errorf("body = %q, want the traffic total", body)
	}
	if !strings.Contains(body, "NAS (5.0 MiB)") {
		t.Errorf("body = %q, want the named top device", body)
	}
	if !strings.Contains(body, "portscan 3") {
		t.Errorf("body = %q, want weighted alert counts", body)
	}
	if !strings.Contains(body, "New devices: 1") {
		t.Errorf("body = %q, want new device count", body)
	}
}
