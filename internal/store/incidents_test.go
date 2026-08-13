package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestIncidentGroupsAndSplits(t *testing.T) {
	st, _ := testStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("203.0.113.5")

	insert := func(at time.Time, detector string, sev model.Severity) model.Alert {
		a, err := st.InsertAlert(ctx, model.Alert{
			Time: at, Detector: detector, Severity: sev, Source: src,
			Title: detector + " event", Count: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.AttachToIncident(ctx, a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	// Three alerts close together, two detectors: one incident.
	insert(base, "portscan", model.SeverityWarning)
	insert(base.Add(5*time.Minute), "portscan", model.SeverityWarning)
	insert(base.Add(10*time.Minute), "feeds", model.SeverityCritical)

	list, err := st.ListIncidents(ctx, IncidentFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("incidents = %d, want 1", len(list))
	}
	in := list[0]
	if in.AlertCount != 3 {
		t.Errorf("alert count = %d, want 3", in.AlertCount)
	}
	// The episode takes the highest severity seen and the union of detectors.
	if in.Severity != string(model.SeverityCritical) {
		t.Errorf("severity = %q, want critical", in.Severity)
	}
	if len(in.Detectors) != 2 {
		t.Errorf("detectors = %v, want two", in.Detectors)
	}

	// After a long quiet period, the next alert starts a new episode.
	insert(base.Add(5*time.Hour), "portscan", model.SeverityWarning)
	list, _ = st.ListIncidents(ctx, IncidentFilter{})
	if len(list) != 2 {
		t.Fatalf("incidents after the gap = %d, want 2", len(list))
	}
}

func TestAckIncidentAcksItsAlerts(t *testing.T) {
	st, _ := testStore(t)
	ctx := context.Background()
	src := netip.MustParseAddr("203.0.113.9")
	a, _ := st.InsertAlert(ctx, model.Alert{
		Time: time.Now(), Detector: "rate", Severity: model.SeverityWarning,
		Source: src, Title: "burst", Count: 1,
	})
	id, err := st.AttachToIncident(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AckIncident(ctx, id); err != nil {
		t.Fatal(err)
	}
	full, err := st.IncidentByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !full.Ack {
		t.Error("incident should be acknowledged")
	}
	if len(full.Alerts) != 1 || !full.Alerts[0].Ack {
		t.Errorf("alerts should be acknowledged with the incident: %+v", full.Alerts)
	}
	// Unacked listing no longer shows it.
	open, _ := st.ListIncidents(ctx, IncidentFilter{UnackedOnly: true})
	if len(open) != 0 {
		t.Errorf("unacked = %d, want 0", len(open))
	}
}

func TestMuteRules(t *testing.T) {
	st, _ := testStore(t)
	ctx := context.Background()

	if _, err := st.AddMuteRule(ctx, MuteRule{}); err == nil {
		t.Error("an empty rule would mute everything and must be refused")
	}
	if _, err := st.AddMuteRule(ctx, MuteRule{Prefix: "nonsense"}); err == nil {
		t.Error("an invalid prefix must be refused")
	}

	r, err := st.AddMuteRule(ctx, MuteRule{Detector: "feeds", Prefix: "239.255.255.250/32", Reason: "SSDP"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !r.Matches("feeds", netip.MustParseAddr("239.255.255.250"), 1900, now) {
		t.Error("rule should match its own criteria")
	}
	if r.Matches("portscan", netip.MustParseAddr("239.255.255.250"), 1900, now) {
		t.Error("a different detector must not match")
	}
	if r.Matches("feeds", netip.MustParseAddr("8.8.8.8"), 1900, now) {
		t.Error("a different source must not match")
	}

	// Expiry.
	past := now.Add(-time.Hour)
	expired := MuteRule{Detector: "feeds", Expires: &past}
	if expired.Matches("feeds", netip.MustParseAddr("8.8.8.8"), 0, now) {
		t.Error("an expired rule must not match")
	}

	rules, _ := st.ListMuteRules(ctx)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	removed, err := st.DeleteMuteRule(ctx, r.ID)
	if err != nil || !removed {
		t.Fatalf("delete = %v, %v", removed, err)
	}
	if again, _ := st.DeleteMuteRule(ctx, r.ID); again {
		t.Error("deleting twice must report not-found")
	}
}
