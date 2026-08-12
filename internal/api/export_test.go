package api

import (
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestExportFlowsCSV(t *testing.T) {
	srv, st := newTestServer(t, "none")
	// One hour before the server's fixed clock, safely inside the default
	// 24h export window (which is half-open and excludes "now" itself).
	err := st.WriteFlows([]model.Flow{{
		Start: time.Unix(1_700_000_000-3600, 0), End: time.Unix(1_700_000_000-3599, 0),
		SrcIP: netip.MustParseAddr("192.168.1.2"), DstIP: netip.MustParseAddr("1.1.1.1"),
		SrcPort: 40000, DstPort: 443, Proto: model.ProtoTCP, Dir: model.DirLANtoWAN,
		OutBytes: 1000, OutPackets: 4, InBytes: 5000, InPackets: 6, DstName: "one.one.one.one",
	}})
	if err != nil {
		t.Fatal(err)
	}

	resp := do(t, srv.Handler(), "GET", "/api/export/flows.csv", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("export = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content-type = %q, want text/csv", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "skopos-flows-") {
		t.Errorf("content-disposition = %q, want an attachment filename", cd)
	}
	rows, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("csv rows = %d, want header + 1 flow", len(rows))
	}
	if rows[0][0] != "start" || rows[1][2] != "192.168.1.2" || rows[1][12] != "one.one.one.one" {
		t.Errorf("unexpected csv content: %v", rows)
	}
}

func TestExportDevicesAndAlertsCSV(t *testing.T) {
	srv, st := newTestServer(t, "none")
	if _, err := st.UpsertDevice(t.Context(), "aa:bb:cc:dd:ee:ff", "192.168.1.9", "nas", "UGREEN"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceLabel(t.Context(), "aa:bb:cc:dd:ee:ff", "Mein NAS"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAlert(t.Context(), model.Alert{
		Detector: "portscan", Severity: model.SeverityWarning,
		Source: netip.MustParseAddr("203.0.113.5"), Title: "Port scan detected",
	}); err != nil {
		t.Fatal(err)
	}

	resp := do(t, srv.Handler(), "GET", "/api/export/devices.csv", "", nil, nil)
	rows, _ := csv.NewReader(resp.Body).ReadAll()
	if len(rows) != 2 || rows[1][0] != "Mein NAS" {
		t.Errorf("devices csv: %v", rows)
	}

	resp = do(t, srv.Handler(), "GET", "/api/export/alerts.csv", "", nil, nil)
	rows, _ = csv.NewReader(resp.Body).ReadAll()
	if len(rows) != 2 || rows[1][4] != "203.0.113.5" {
		t.Errorf("alerts csv: %v", rows)
	}
}

func TestWakeDevice(t *testing.T) {
	srv, st := newTestServer(t, "none")
	var woken string
	srv.deps.WakeFunc = func(mac string) error {
		woken = mac
		return nil
	}

	// Invalid MAC → 400, nothing sent.
	resp := do(t, srv.Handler(), "POST", "/api/devices/not-a-mac/wake", "", nil, nil)
	if resp.StatusCode != 400 {
		t.Errorf("bad mac = %d, want 400", resp.StatusCode)
	}
	if woken != "" {
		t.Error("bad mac must not trigger a wake")
	}

	resp = do(t, srv.Handler(), "POST", "/api/devices/aa:bb:cc:dd:ee:ff/wake", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("wake = %d, want 200", resp.StatusCode)
	}
	if woken != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("woken = %q", woken)
	}
	// The action lands in the audit log.
	entries, _ := st.ListAudit(t.Context(), 10)
	found := false
	for _, e := range entries {
		if e.Action == "device_wake" && e.Target == "aa:bb:cc:dd:ee:ff" {
			found = true
		}
	}
	if !found {
		t.Error("wake was not audited")
	}
}

func TestDeviceDetail(t *testing.T) {
	srv, st := newTestServer(t, "none")
	if _, err := st.UpsertDevice(t.Context(), "aa:bb:cc:dd:ee:01", "192.168.1.50", "tv", ""); err != nil {
		t.Fatal(err)
	}
	// One flow from the device an hour before the fixed clock.
	err := st.WriteFlows([]model.Flow{{
		Start: time.Unix(1_700_000_000-3600, 0), End: time.Unix(1_700_000_000-3599, 0),
		SrcIP: netip.MustParseAddr("192.168.1.50"), DstIP: netip.MustParseAddr("142.250.185.78"),
		SrcPort: 40000, DstPort: 443, Proto: model.ProtoTCP, Dir: model.DirLANtoWAN,
		OutBytes: 2000, OutPackets: 3, InBytes: 9000, InPackets: 8, DstName: "youtube.com",
	}})
	if err != nil {
		t.Fatal(err)
	}

	resp := do(t, srv.Handler(), "GET", "/api/devices/aa:bb:cc:dd:ee:01/detail", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("detail = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Series       []map[string]any `json:"series"`
		Destinations []struct {
			Address string `json:"address"`
			Name    string `json:"name"`
		} `json:"destinations"`
		Ports []struct {
			Port  int    `json:"port"`
			Proto string `json:"proto"`
		} `json:"ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Series) == 0 || len(out.Destinations) == 0 || len(out.Ports) == 0 {
		t.Fatalf("detail incomplete: series=%d dst=%d ports=%d", len(out.Series), len(out.Destinations), len(out.Ports))
	}
	if out.Destinations[0].Name != "youtube.com" {
		t.Errorf("destination name = %q, want DNS enrichment", out.Destinations[0].Name)
	}
	if out.Ports[0].Port != 443 || out.Ports[0].Proto != "tcp" {
		t.Errorf("ports = %+v", out.Ports)
	}

	// Unknown MAC → 404.
	resp = do(t, srv.Handler(), "GET", "/api/devices/00:00:00:00:00:00/detail", "", nil, nil)
	if resp.StatusCode != 404 {
		t.Errorf("unknown device = %d, want 404", resp.StatusCode)
	}
}
