package reputation

import (
	"context"
	"encoding/json"
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
	if info.Verdict != VerdictReported {
		t.Errorf("verdict = %q, want %q for 1200 reports across 57 targets",
			info.Verdict, VerdictReported)
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
func TestUnknownAddressIsNotCleared(t *testing.T) {
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
	if info.Verdict != VerdictNoReports {
		t.Errorf("verdict = %q, want %q: both sources answered and neither held anything",
			info.Verdict, VerdictNoReports)
	}
	if info.AbuseReports != 0 {
		t.Errorf("reports = %d, want 0", info.AbuseReports)
	}
	// Each source still reports that it looked and found nothing.
	if len(info.Signals) != 2 {
		t.Fatalf("signals = %+v, want one per public source", info.Signals)
	}
	for _, sig := range info.Signals {
		if sig.State != StateClean {
			t.Errorf("%s: state = %q, want %q", sig.Source, sig.State, StateClean)
		}
		if sig.Reports != nil || sig.Targets != nil {
			t.Errorf("%s published counts for an address it has never seen", sig.Source)
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
	s.Listed = func(netip.Addr) []string { return []string{"spamhaus_drop"} }
	s.Geo = func(netip.Addr) (string, bool) { return "NL", true }

	info, err := s.Lookup(context.Background(), netip.MustParseAddr("195.178.110.48"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Verdict != VerdictListed {
		t.Errorf("verdict = %q, want %q from the blocklist match", info.Verdict, VerdictListed)
	}
	// The signal has to name the list. "On a blocklist" leaves the reader
	// unable to weigh the match, and weighing it is the whole decision: a
	// Spamhaus DROP entry and somebody's homemade list are not the same claim.
	var named bool
	for _, sig := range info.Signals {
		if sig.Source != "blocklists" {
			continue
		}
		named = true
		if len(sig.Lists) != 1 || sig.Lists[0] != "spamhaus_drop" {
			t.Errorf("lists = %v, want the matching list named", sig.Lists)
		}
	}
	if !named {
		t.Error("no blocklists signal at all")
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

// Each source keeps its own figures. Collapsing "1 report" and "1430 reports"
// into a single number is precisely what 0.5.0 removed: those are different
// claims from different sensor networks, and only the reader can weigh them.
func TestEachSourceKeepsItsOwnFigures(t *testing.T) {
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
	if info.Verdict != VerdictReported {
		t.Errorf("verdict = %q, want %q", info.Verdict, VerdictReported)
	}
	got := map[string]int{}
	for _, sig := range info.Signals {
		if sig.Reports != nil {
			got[sig.Source] = *sig.Reports
		}
	}
	if got["dshield"] != 1 || got["blocklist.de"] != 1430 {
		t.Errorf("per-source reports = %v, want dshield 1 and blocklist.de 1430", got)
	}
	if info.AbuseReports != 1430 {
		t.Errorf("reports = %d, want the highest count any source gave", info.AbuseReports)
	}
}

// The regression guard for the bug this release exists to fix. Whatever else
// the payload grows, it must never again carry a number Skopos invented: the
// operator saw 70% on practically every address, and 70 was a constant.
func TestPayloadCarriesNoInventedScore(t *testing.T) {
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/ip/"):
			_, _ = w.Write([]byte(`{"ip":{"count":"1200","attacks":"57"}}`))
		case strings.HasPrefix(r.URL.Path, "/api.php"):
			_, _ = w.Write([]byte("attacks: 640\nreports: 1430\n"))
		default:
			_, _ = w.Write([]byte(`{"name":"HOSTER"}`))
		}
	}))
	s.Listed = func(netip.Addr) []string { return []string{"firehol_level1"} }

	info, err := s.Lookup(context.Background(), netip.MustParseAddr("195.178.110.48"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"abuse_score", "\"score\"", "percent"} {
		if strings.Contains(string(body), banned) {
			t.Errorf("payload still carries %s: %s", banned, body)
		}
	}
	// Every number that survives has to be traceable to a source that
	// published it.
	if info.AbuseReports != 1430 {
		t.Errorf("reports = %d, want blocklist.de's 1430", info.AbuseReports)
	}
	if info.Targets != 57 {
		t.Errorf("targets = %d, want DShield's 57", info.Targets)
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

// The 0.3.0 failure, guarded. A decode into the DShield response struct
// succeeds on any well-formed JSON and leaves every field zero; reading that
// zero as "no reports" is how the card showed a confident green nothing beside
// a critical alert for an address with over a thousand reports against it.
func TestDShieldUnrecognisedReplyIsNotNoReports(t *testing.T) {
	for _, body := range []string{
		`{"error":"rate limited"}`,
		`{"data":{"count":1430}}`,
		`{}`,
		`{"ip":null}`,
	} {
		s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/ip/") {
				_, _ = w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusBadGateway)
		}))
		info, _ := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9"))
		for _, sig := range info.Signals {
			if sig.Source != "dshield" {
				continue
			}
			if sig.State != StateError {
				t.Errorf("body %s produced state %q (%q), want %q",
					body, sig.State, sig.Detail, StateError)
			}
			if sig.Reports != nil {
				t.Errorf("body %s produced a report count of %d out of nothing",
					body, *sig.Reports)
			}
		}
		if info.Source == "dshield" {
			t.Errorf("body %s must not be credited to dshield as an answer", body)
		}
	}
}

// A reply whose report count fails to parse — a thousands separator is enough —
// used to leave the other key's zero standing as a confident answer.
func TestBlocklistDEPartialParseIsNotAZero(t *testing.T) {
	for _, body := range []string{
		"attacks: 0\nreports: 1,430",
		"attacks: 0",
		"1430",
		"<html>rate limited</html>",
	} {
		attacks, reports, ok := parseBlocklistDE(body)
		if ok {
			t.Errorf("body %q parsed as attacks=%d reports=%d; it should be no answer",
				body, attacks, reports)
		}
	}
	if a, r, ok := parseBlocklistDE("attacks: 3\nreports: 7"); !ok || a != 3 || r != 7 {
		t.Errorf("a complete reply must parse: %d %d %v", a, r, ok)
	}
}

// "Not on your blocklists" is a positive claim of a negative. Asserting it
// against a set that never loaded is the same error in a different place.
func TestNoBlocklistsLoadedIsNotAClearance(t *testing.T) {
	s := testService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	s.Listed = func(netip.Addr) []string { return nil }
	s.FeedsLoaded = func() bool { return false }

	info, _ := s.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9"))
	for _, sig := range info.Signals {
		if sig.Source == "blocklists" && sig.Detail == "not on your blocklists" {
			t.Error("claimed the address is not listed while no blocklist was loaded")
		}
	}
}
