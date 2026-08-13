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
	s.BlocklistDEURL = srv.URL + "/api.php"
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

// An address nobody has data on is unknown, not clean. Reporting it as a
// confident zero is the one answer the card must never give: it sat next to a
// critical alert and read as reassurance.
func TestUnknownAddressHasNoScore(t *testing.T) {
	// DShield answers with nulls for addresses it has never seen; blocklist.de
	// answers with zeroes.
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/ip/"):
			_, _ = w.Write([]byte(`{"ip":{"number":"1.1.1.1","count":null,"attacks":null,"maxdate":null}}`))
		case strings.HasPrefix(r.URL.Path, "/api.php"):
			_, _ = w.Write([]byte("attacks: 0\nreports: 0\n"))
		default:
			_, _ = w.Write([]byte(`{"name":"CLOUDFLARE"}`))
		}
	}))
	info, err := s.Lookup(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.AbuseScore != nil {
		t.Errorf("score = %d, want none: no source had data", *info.AbuseScore)
	}
	if info.AbuseReports != 0 {
		t.Errorf("reports = %d, want 0", info.AbuseReports)
	}
	// Each source still reports that it looked and found nothing.
	if len(info.Signals) != 2 {
		t.Fatalf("signals = %+v, want one per public source", info.Signals)
	}
	for _, sig := range info.Signals {
		if sig.Score != nil {
			t.Errorf("%s reported a score for an address it does not know", sig.Source)
		}
	}
}

// The evidence Skopos already holds counts. An address on a downloaded
// blocklist used to trip a critical alert while the card beside it showed
// nothing at all.
func TestBlocklistMembershipCounts(t *testing.T) {
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/ip/"):
			_, _ = w.Write([]byte(`{"ip":{"count":null,"attacks":null}}`))
		case strings.HasPrefix(r.URL.Path, "/api.php"):
			_, _ = w.Write([]byte("attacks: 0\nreports: 0\n"))
		default:
			_, _ = w.Write([]byte(`{"name":"TECHOFF_SRV_LIMITED","country":"AD"}`))
		}
	}))
	s.Listed = func(netip.Addr) bool { return true }
	s.Geo = func(netip.Addr) (string, bool) { return "NL", true }

	info, err := s.Lookup(context.Background(), netip.MustParseAddr("195.178.110.48"))
	if err != nil {
		t.Fatal(err)
	}
	if info.AbuseScore == nil || *info.AbuseScore != listedScore {
		t.Errorf("score = %v, want %d from the blocklist match", info.AbuseScore, listedScore)
	}
	// GeoIP knows where the traffic comes from; the registry only knows where
	// the holder is incorporated.
	if info.Country != "NL" || info.CountrySource != "geoip" {
		t.Errorf("country = %q from %q, want NL from geoip", info.Country, info.CountrySource)
	}
	if info.Org != "TECHOFF_SRV_LIMITED" {
		t.Errorf("org = %q", info.Org)
	}
}

// The strongest reading wins: one source with evidence should not be diluted
// by others that have never heard of the address.
func TestStrongestSignalWins(t *testing.T) {
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/ip/"):
			_, _ = w.Write([]byte(`{"ip":{"count":"1","attacks":"1"}}`))
		case strings.HasPrefix(r.URL.Path, "/api.php"):
			_, _ = w.Write([]byte("attacks: 640\nreports: 1430\n"))
		default:
			_, _ = w.Write([]byte(`{"name":"HOSTER"}`))
		}
	}))
	info, err := s.Lookup(context.Background(), netip.MustParseAddr("195.178.110.48"))
	if err != nil {
		t.Fatal(err)
	}
	if info.AbuseScore == nil || *info.AbuseScore != 95 {
		t.Errorf("score = %v, want 95 from blocklist.de rather than DShield's 15", info.AbuseScore)
	}
	if info.AbuseReports != 1430 {
		t.Errorf("reports = %d, want the highest count any source gave", info.AbuseReports)
	}
}

func TestParseBlocklistDE(t *testing.T) {
	cases := []struct {
		name             string
		body             string
		attacks, reports int
		ok               bool
	}{
		{"normal", "attacks: 12\nreports: 34\n", 12, 34, true},
		{"no spaces", "attacks:0\nreports:0", 0, 0, true},
		{"mixed case and extra keys", "Attacks: 3\nunknown: x\nReports: 9", 3, 9, true},
		{"empty", "", 0, 0, false},
		{"html error page", "<html><body>nope</body></html>", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, r, ok := parseBlocklistDE(tc.body)
			if a != tc.attacks || r != tc.reports || ok != tc.ok {
				t.Errorf("= %d, %d, %v; want %d, %d, %v", a, r, ok, tc.attacks, tc.reports, tc.ok)
			}
		})
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
