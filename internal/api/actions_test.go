package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// TestActionTokenRoundTrip covers the happy path and every way a token can be
// wrong. These links travel through a push notification, so a forged or
// stale one must never do anything.
func TestActionTokenRoundTrip(t *testing.T) {
	s, _ := newTestServer(t, "none")
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	token := s.mintAction(actionBlock, "203.0.113.5", "portscan", now)
	kind, target, detector, ok := s.parseAction(token, now)
	if !ok || kind != actionBlock || target != "203.0.113.5" || detector != "portscan" {
		t.Fatalf("round trip = %q %q %q %v", kind, target, detector, ok)
	}

	// Expired.
	if _, _, _, ok := s.parseAction(token, now.Add(actionTTL+time.Minute)); ok {
		t.Error("an expired token must not verify")
	}

	// Tampered payload: swap the target for another address, keeping the
	// original signature.
	raw, sig, _ := strings.Cut(token, ".")
	forged := strings.Replace(raw, raw[:4], "AAAA", 1) + "." + sig
	if _, _, _, ok := s.parseAction(forged, now); ok {
		t.Error("a tampered payload must not verify")
	}

	// Tampered signature.
	if _, _, _, ok := s.parseAction(raw+".AAAA", now); ok {
		t.Error("a tampered signature must not verify")
	}

	// Structurally broken input.
	for _, bad := range []string{"", ".", "no-dot", "!!!.!!!"} {
		if _, _, _, ok := s.parseAction(bad, now); ok {
			t.Errorf("%q must not verify", bad)
		}
	}

	// A token minted by a different key (different signer) must not verify
	// here — that is the whole point of signing them.
	other, _ := newTestServer(t, "none")
	if _, _, _, ok := s.parseAction(other.mintAction(actionBlock, "203.0.113.5", "portscan", now), now); ok {
		t.Error("a token from another instance must not verify")
	}
}

func TestActionEndpointBlocks(t *testing.T) {
	s, _ := newTestServer(t, "none")
	s.deps.Config.Server.ExternalURL = "https://skopos.example.test"

	token := s.mintAction(actionBlock, "203.0.113.5", "portscan", s.clock())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/actions/"+token, nil)
	req.SetPathValue("token", token)
	s.handleAction(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Blocked") {
		t.Errorf("body = %s", rec.Body.String())
	}
	blocks, err := s.deps.Store.ActiveBlocks(req.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0].Prefix.String() != "203.0.113.5/32" {
		t.Fatalf("blocks = %+v", blocks)
	}
	// The block is temporary, so a tap from a phone cannot create a
	// permanent rule nobody remembers.
	if blocks[0].Expires == nil {
		t.Error("a notification block must expire")
	}

	// An invalid token changes nothing.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/actions/bogus", nil)
	req2.SetPathValue("token", "bogus")
	s.handleAction(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("invalid token status = %d, want 403", rec2.Code)
	}
	blocks, _ = s.deps.Store.ActiveBlocks(req.Context())
	if len(blocks) != 1 {
		t.Errorf("a rejected action must not change state, blocks = %d", len(blocks))
	}
}

func TestActionEndpointMutes(t *testing.T) {
	s, _ := newTestServer(t, "none")
	token := s.mintAction(actionMute, "203.0.113.9", "feeds", s.clock())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/actions/"+token, nil)
	req.SetPathValue("token", token)
	s.handleAction(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rules, err := s.deps.Store.ListMuteRules(req.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Detector != "feeds" || rules[0].Prefix != "203.0.113.9/32" {
		t.Fatalf("rules = %+v", rules)
	}
	// Muting must not have blocked anything.
	blocks, _ := s.deps.Store.ActiveBlocks(req.Context())
	if len(blocks) != 0 {
		t.Errorf("muting must not block, got %d blocks", len(blocks))
	}
}

func TestAlertActionsNeedAnExternalURL(t *testing.T) {
	s, _ := newTestServer(t, "none")
	// Without an external URL the buttons would point at localhost and only
	// frustrate, so there are none.
	s.deps.Config.Server.ExternalURL = ""
	if got := s.AlertActions(testAlert()); got != nil {
		t.Errorf("actions without an external URL = %+v, want none", got)
	}

	s.deps.Config.Server.ExternalURL = "https://skopos.example.test/"
	got := s.AlertActions(testAlert())
	if len(got) != 2 {
		t.Fatalf("actions = %+v, want two", got)
	}
	for _, a := range got {
		if !strings.HasPrefix(a.URL, "https://skopos.example.test/api/actions/") {
			t.Errorf("action URL = %q", a.URL)
		}
	}
}

// testAlert is a minimal alert with a public source.
func testAlert() model.Alert {
	return model.Alert{
		ID: 1, Time: time.Unix(1_700_000_000, 0), Detector: "portscan",
		Severity: model.SeverityWarning, Source: netip.MustParseAddr("203.0.113.5"),
		Title: "Vertical port scan", Count: 1,
	}
}
