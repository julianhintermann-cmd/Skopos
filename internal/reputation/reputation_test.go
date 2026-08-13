package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testService points a Service at a stub serving both upstreams.
func testService(t *testing.T, h http.Handler) *Service {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	s := New(func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) })
	s.RDAPBase = srv.URL
	s.DShieldBase = srv.URL
	return s
}

// bothSourcesMux answers RDAP and DShield, counting calls to each.
func bothSourcesMux(rdapCalls, dshieldCalls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/ip/"):
			*rdapCalls++
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{"name":"EXAMPLE-NET","handle":"NET-203-0-113-0-1","country":"NL"}`))
		case strings.HasPrefix(r.URL.Path, "/api/ip/"):
			*dshieldCalls++
			_, _ = w.Write([]byte(`{"ip":{"number":"203.0.113.5","count":"1200","attacks":"57",` +
				`"mindate":"2026-07-01","maxdate":"2026-08-12","asname":"EVIL-AS","ascountry":"RU"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestLookupCombinesSources(t *testing.T) {
	var rdap, dshield int
	s := testService(t, bothSourcesMux(&rdap, &dshield))

	info, err := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.5"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Org != "EXAMPLE-NET" || info.Handle != "NET-203-0-113-0-1" {
		t.Errorf("rdap fields missing: %+v", info)
	}
	// RDAP wins on country because the registry allocation is authoritative.
	if info.Country != "NL" {
		t.Errorf("country = %q, want NL", info.Country)
	}
	if info.AbuseReports != 1200 || info.Targets != 57 {
		t.Errorf("dshield counts = %d/%d, want 1200/57", info.AbuseReports, info.Targets)
	}
	if info.AbuseScore == nil || *info.AbuseScore < 50 {
		t.Errorf("score = %v, want a high score for 1200 reports across 57 targets", info.AbuseScore)
	}
	if info.LastReport != "2026-08-12" || info.Source != "dshield" {
		t.Errorf("report metadata missing: %+v", info)
	}
	if rdap != 1 || dshield != 1 {
		t.Errorf("calls rdap=%d dshield=%d, want 1/1", rdap, dshield)
	}
}

func TestLookupCaches(t *testing.T) {
	var rdap, dshield int
	s := testService(t, bothSourcesMux(&rdap, &dshield))
	addr := netip.MustParseAddr("203.0.113.5")

	for i := 0; i < 3; i++ {
		if _, err := s.Lookup(context.Background(), addr); err != nil {
			t.Fatal(err)
		}
	}
	if rdap != 1 || dshield != 1 {
		t.Errorf("cached lookups still hit upstream: rdap=%d dshield=%d", rdap, dshield)
	}
}

func TestLookupDegradesIndependently(t *testing.T) {
	// RDAP down, DShield up: the answer still carries the attack history.
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/ip/") {
			_, _ = w.Write([]byte(`{"ip":{"count":5,"attacks":1}}`))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	info, err := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9"))
	if err != nil {
		t.Fatalf("one failing source must not fail the lookup: %v", err)
	}
	if info.AbuseReports != 5 {
		t.Errorf("reports = %d, want 5", info.AbuseReports)
	}

	// Both down: an error, so the UI can say so.
	s2 := testService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	if _, err := s2.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9")); err == nil {
		t.Error("expected an error when every source fails")
	}
}

func TestUnknownAddressScoresZero(t *testing.T) {
	// DShield answers with nulls for addresses it has never seen.
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/ip/") {
			_, _ = w.Write([]byte(`{"ip":{"number":"1.1.1.1","count":null,"attacks":null,"maxdate":null}}`))
			return
		}
		_, _ = w.Write([]byte(`{"name":"CLOUDFLARE"}`))
	}))
	info, err := s.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.AbuseScore == nil || *info.AbuseScore != 0 {
		t.Errorf("score = %v, want 0 for an unreported address", info.AbuseScore)
	}
	if info.AbuseReports != 0 {
		t.Errorf("reports = %d, want 0", info.AbuseReports)
	}
}

func TestDShieldScore(t *testing.T) {
	cases := []struct{ reports, targets, want int }{
		{0, 0, 0},
		{1, 0, 15},
		{50, 3, 35},       // 30 (≥10 reports) + 5 (≥2 targets)
		{150, 3, 50},      // 45 (≥100 reports) + 5
		{5000, 200, 85},   // 60 + 25
		{50000, 500, 100}, // 75 + 25
	}
	for _, c := range cases {
		if got := dshieldScore(c.reports, c.targets); got != c.want {
			t.Errorf("dshieldScore(%d, %d) = %d, want %d", c.reports, c.targets, got, c.want)
		}
	}
}
