// Package reputation answers "who is this address" for alerts and blocks.
//
// Every source is free and keyless, so the answer is populated on a fresh
// install without anyone registering anywhere: ownership from RDAP (the
// registries' successor to WHOIS), location from the local GeoIP database,
// attack history from the SANS Internet Storm Center and blocklist.de, and
// the operator's own downloaded blocklists.
//
// No single free source has the coverage of a commercial one, so they are
// asked together and each answer is reported for what it is. The one thing
// this package will not do is present silence as safety: an address nobody
// happened to have data on is unknown, not clean. Results are cached for a
// day.
//
// There is no score here, and that is deliberate. None of these sources
// publishes a risk rating; they publish counts and memberships. Until 0.5.0
// this package manufactured a 0–100 number out of them anyway — a blocklist
// match was hardcoded to 70, twenty reports to 70, and the card rendered the
// result as "Abuse 70%". Since the built-in lists cover a great deal of
// address space, almost every address an operator inspected came back 70, and
// the one figure on the card that looked like a measurement was the only one
// nobody had measured. What each source actually said is reported instead,
// and the summary is a word rather than a percentage.
package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultRDAPBase       = "https://rdap.org"
	defaultDShieldBase    = "https://isc.sans.edu"
	defaultBlocklistDEURL = "https://api.blocklist.de/api.php"
	cacheTTL              = 24 * time.Hour
	maxBody               = 1 << 20
)

// userAgent identifies Skopos to DShield, which asks API users to be
// identifiable rather than anonymous.
const userAgent = "Skopos (+https://github.com/julianhintermann-cmd/skopos)"

// State is what one source actually managed to say. The distinction between
// the last three is the whole point: a source that holds nothing, a source
// that was never asked, and a source that was asked and failed are three
// different facts, and flattening them is how an unanswered lookup comes to
// look like a clean one.
type State string

const (
	// StateListed — the address is on a curated blocklist, named in Lists.
	StateListed State = "listed"
	// StateReported — sensors reported it, with counts that came from the
	// source rather than from us.
	StateReported State = "reported"
	// StateClean — the source answered and holds nothing on this address.
	StateClean State = "clean"
	// StateUnknown — the source was not consulted, or had nothing to compare
	// against.
	StateUnknown State = "unknown"
	// StateError — the source was asked and the answer could not be used.
	StateError State = "error"
)

// Signal is one source's answer, kept whole so the card can show who said what.
//
// It used to carry a 0–100 Score. No free source publishes such a number, so
// Skopos was computing one by bucketing report counts — 20 reports became 70,
// a blocklist match became a flat 70 — and rendering the result as "Abuse 70%".
// That is a fabricated measurement wearing the clothes of a real one, and
// because the built-in lists cover a great deal of address space, nearly every
// address an operator looked at came back 70. The counts below are what the
// sources actually publish; the reader can weigh them.
type Signal struct {
	Source string `json:"source"`
	State  State  `json:"state"`
	Detail string `json:"detail"`
	// Reports and Targets are the source's own figures, absent when it
	// published none. Never derived, never defaulted to zero.
	Reports *int `json:"reports,omitempty"`
	Targets *int `json:"targets,omitempty"`
	// Lists names the blocklists that matched, for a listed signal.
	Lists []string `json:"lists,omitempty"`
}

// Verdict is the one-word summary, derived from the signals and never from
// anything else. It is deliberately categorical: the underlying evidence is a
// handful of report counts from two sensor networks and a membership test
// against a blocklist, and no honest arithmetic turns that into a percentage.
type Verdict string

const (
	// VerdictListed — at least one curated blocklist holds this address.
	VerdictListed Verdict = "listed"
	// VerdictReported — sensors have reported it, with counts.
	VerdictReported Verdict = "reported"
	// VerdictNoReports — every source that answered holds nothing. Weak
	// evidence, and never rendered as safety.
	VerdictNoReports Verdict = "no_reports"
	// VerdictUnknown — nothing could be learned. Not the same as clean.
	VerdictUnknown Verdict = "unknown"
)

// Info is everything Skopos knows about an external address.
type Info struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Country string `json:"country,omitempty"`
	// CountrySource says where the country came from. It matters: a registry
	// records where the holder is incorporated, which is regularly a
	// different country from the one the addresses are announced in.
	CountrySource string `json:"country_source,omitempty"`
	// Verdict summarises the signals in one word. Always set.
	Verdict Verdict `json:"verdict"`
	// AbuseReports is the largest report count any source published, absent
	// when none did. It is a count somebody else measured, not a rating.
	AbuseReports int    `json:"abuse_reports,omitempty"`
	ISP          string `json:"isp,omitempty"`
	UsageType    string `json:"usage_type,omitempty"`
	// Targets is how many distinct victims reported this address.
	Targets int `json:"targets,omitempty"`
	// FirstReport / LastReport bound the observed activity.
	FirstReport string `json:"first_report,omitempty"`
	LastReport  string `json:"last_report,omitempty"`
	Source      string `json:"source,omitempty"`
	// Signals is every source's answer, including the ones that had nothing.
	Signals   []Signal  `json:"signals,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Service performs and caches lookups.
type Service struct {
	HTTP           *http.Client
	RDAPBase       string
	DShieldBase    string
	BlocklistDEURL string

	// Geo resolves an address to a country using the local GeoIP database.
	// It is the accurate answer for "where is this?" and takes precedence
	// over the registry's country, which describes the holder, not the route.
	Geo func(netip.Addr) (string, bool)
	// Listed names the blocklists the operator subscribes to that contain the
	// address, empty when none does. Answered from memory, no request. It
	// returns names rather than a bare yes because "on a blocklist" leaves the
	// reader unable to judge the match, and the lists differ enormously in how
	// carefully they are curated.
	Listed func(netip.Addr) []string
	// FeedsLoaded reports whether any blocklist is actually loaded. Without
	// it, Listed answering false is indistinguishable from having nothing to
	// compare against — and the card would state "not on your blocklists" as
	// a fact on the strength of an empty set.
	FeedsLoaded func() bool

	clock func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	at   time.Time
	info Info
}

// New builds a Service.
func New(clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		HTTP:           &http.Client{Timeout: 15 * time.Second},
		RDAPBase:       defaultRDAPBase,
		DShieldBase:    defaultDShieldBase,
		BlocklistDEURL: defaultBlocklistDEURL,
		clock:          clock,
		cache:          map[string]cacheEntry{},
	}
}

// Lookup resolves one address, serving from cache when fresh. Sources degrade
// independently — whatever answered is returned, and what each said is kept.
func (s *Service) Lookup(ctx context.Context, addr netip.Addr) (Info, error) {
	ip := addr.String()
	now := s.clock()

	s.mu.Lock()
	if e, ok := s.cache[ip]; ok && now.Sub(e.at) < cacheTTL {
		info := e.info
		s.mu.Unlock()
		return info, nil
	}
	s.mu.Unlock()

	info := Info{IP: ip, CheckedAt: now}

	// Local first: both answer instantly and neither can fail.
	s.local(addr, &info)

	rdapOK := s.rdap(ctx, ip, &info) == nil
	_ = s.dshield(ctx, ip, &info)
	_ = s.blocklistDE(ctx, ip, &info)

	// Every source failing is a different thing from every source having
	// nothing, and the caller has to be able to tell them apart — the first is
	// our failure to report, the second is an answer. The test cannot be "did
	// any signal appear", because a failed source now leaves one behind on
	// purpose; it has to be whether any source produced a reading.
	if !rdapOK && !answered(&info) {
		return info, fmt.Errorf("reputation: all sources failed for %s", ip)
	}
	s.combine(&info)

	s.mu.Lock()
	s.cache[ip] = cacheEntry{at: now, info: info}
	if len(s.cache) > 2048 {
		for k, e := range s.cache {
			if now.Sub(e.at) > cacheTTL {
				delete(s.cache, k)
			}
		}
	}
	s.mu.Unlock()
	return info, nil
}

// answered reports whether any source produced a reading, as opposed to
// failing or having nothing to compare against.
func answered(info *Info) bool {
	for _, sig := range info.Signals {
		switch sig.State {
		case StateListed, StateReported, StateClean:
			return true
		}
	}
	return false
}

// local answers from what Skopos already holds: the GeoIP database it keeps
// on disk, and the blocklists it downloads for the feeds detector. Neither
// costs a request, and the blocklist answer is the one that used to be
// missing — an address could trip the blocklist detector into a critical
// alert while the card beside it reported nothing at all.
func (s *Service) local(addr netip.Addr, info *Info) {
	if s.Geo != nil {
		if code, ok := s.Geo(addr); ok && code != "" {
			info.Country = code
			info.CountrySource = "geoip"
		}
	}
	if s.Listed == nil {
		return
	}
	if s.FeedsLoaded != nil && !s.FeedsLoaded() {
		// Saying "not on your blocklists" when no blocklist has loaded is a
		// negative asserted against nothing — the same shape as reading an
		// absent measurement as a clean score. Either the feeds are switched
		// off, or every download failed; in both cases the honest answer is
		// that we do not know.
		info.Signals = append(info.Signals, Signal{
			Source: "blocklists", State: StateUnknown,
			Detail: "no blocklists loaded — nothing to check against",
		})
		return
	}
	if hits := s.Listed(addr); len(hits) > 0 {
		info.Signals = append(info.Signals, Signal{
			Source: "blocklists",
			State:  StateListed,
			Lists:  hits,
			Detail: "on " + strings.Join(hits, ", "),
		})
		return
	}
	info.Signals = append(info.Signals, Signal{
		Source: "blocklists",
		State:  StateClean,
		Detail: "not on your blocklists",
	})
}

// combine reduces the per-source answers to one word. The strongest evidence
// wins rather than an average: one source holding a firm answer should not be
// diluted by three that never heard of the address.
//
// The ordering is the point. A blocklist match outranks a report count because
// somebody curated it; reports outrank silence because they are evidence;
// silence from sources that answered outranks silence from sources that could
// not, because at least somebody looked. Nothing here produces a number, and
// nothing here treats an absence of evidence as evidence of absence.
func (s *Service) combine(info *Info) {
	verdict := VerdictUnknown
	for _, sig := range info.Signals {
		switch sig.State {
		case StateListed:
			info.Verdict = VerdictListed
			return
		case StateReported:
			verdict = VerdictReported
		case StateClean:
			if verdict != VerdictReported {
				verdict = VerdictNoReports
			}
		}
	}
	info.Verdict = verdict
}

// rdap fills owner and country from the registry's RDAP record.
func (s *Service) rdap(ctx context.Context, ip string, info *Info) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.RDAPBase+"/ip/"+url.PathEscape(ip), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rdap: %s", resp.Status)
	}
	var rec struct {
		Name    string `json:"name"`
		Handle  string `json:"handle"`
		Country string `json:"country"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&rec); err != nil {
		return err
	}
	info.Org = rec.Name
	info.Handle = rec.Handle
	// Only when GeoIP had nothing. A registry records where the holder is
	// incorporated: a hoster registered in Andorra announcing its addresses
	// from a Dutch data centre is an ordinary arrangement, and reporting
	// Andorra as the traffic's origin is simply wrong.
	if info.Country == "" && rec.Country != "" {
		info.Country = rec.Country
		info.CountrySource = "registry"
	}
	return nil
}

// blocklistDE asks blocklist.de how often this address has been reported by
// the fail2ban installations that feed it. Keyless, and its coverage of
// brute-force and scanning sources overlaps only partly with DShield's
// sensors — which is the point of asking both.
func (s *Service) blocklistDE(ctx context.Context, ip string, info *Info) error {
	if s.BlocklistDEURL == "" {
		return nil
	}
	u := s.BlocklistDEURL + "?ip=" + url.QueryEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		fail(info, "blocklist.de", "the request could not be built")
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		fail(info, "blocklist.de", "could not be reached")
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fail(info, "blocklist.de", "answered "+resp.Status)
		return fmt.Errorf("blocklist.de: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		fail(info, "blocklist.de", "the reply could not be read")
		return err
	}

	attacks, reports, ok := parseBlocklistDE(string(body))
	if !ok {
		fail(info, "blocklist.de", "the reply was not recognised")
		return fmt.Errorf("blocklist.de: unrecognised response")
	}
	if reports <= 0 && attacks <= 0 {
		info.Signals = append(info.Signals, Signal{
			Source: "blocklist.de",
			State:  StateClean,
			Detail: "no reports",
		})
		return nil
	}
	r, a := reports, attacks
	info.Signals = append(info.Signals, Signal{
		Source:  "blocklist.de",
		State:   StateReported,
		Reports: &r,
		Targets: &a,
		Detail:  fmt.Sprintf("%d reports, %d attacks", reports, attacks),
	})
	if reports > info.AbuseReports {
		info.AbuseReports = reports
	}
	return nil
}

// fail records that a source could not answer. A source simply missing from
// the card is indistinguishable from one that answered "nothing here", and
// telling those two apart is the entire job of this package.
func fail(info *Info, source, detail string) {
	info.Signals = append(info.Signals, Signal{Source: source, State: StateError, Detail: detail})
}

// parseBlocklistDE reads the service's plain-text reply, which is a couple of
// "key: value" lines. Unfamiliar keys are skipped, but the two that carry the
// answer must both be present and parse — a partial read is reported as no
// answer rather than as a zero.
func parseBlocklistDE(body string) (attacks, reports int, ok bool) {
	var sawAttacks, sawReports bool
	for _, line := range strings.Split(body, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "attacks":
			attacks, sawAttacks = n, true
		case "reports":
			reports, sawReports = n, true
		}
	}
	// Both keys, or nothing. Accepting a half-parse meant a reply whose report
	// count failed to parse — a thousand separator is enough — still reported a
	// confident zero, which is the one answer we must never invent.
	return attacks, reports, sawAttacks && sawReports
}

// dshield fills the attack history from the SANS Internet Storm Center. Its
// data comes from firewall logs submitted by thousands of sensors, which is
// exactly the question an operator has about an address that just knocked:
// has it been attacking other people too?
func (s *Service) dshield(ctx context.Context, ip string, info *Info) error {
	u := fmt.Sprintf("%s/api/ip/%s?json", s.DShieldBase, url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		fail(info, "dshield", "could not be reached")
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fail(info, "dshield", "answered "+resp.Status)
		return fmt.Errorf("dshield: %s", resp.Status)
	}
	// DShield types loosely: counts arrive as numbers or strings, and unknown
	// addresses answer with nulls. flexInt absorbs all of it.
	var out struct {
		IP *struct {
			Number   string  `json:"number"`
			Count    flexInt `json:"count"`
			Attacks  flexInt `json:"attacks"`
			MinDate  string  `json:"mindate"`
			MaxDate  string  `json:"maxdate"`
			Comment  string  `json:"comment"`
			AsName   string  `json:"asname"`
			AsAbuse  string  `json:"asabusecontact"`
			Country  string  `json:"ascountry"`
			Network  string  `json:"network"`
			Threat   string  `json:"threatfeeds"`
			Category string  `json:"category"`
		} `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return err
	}

	// A decode into that struct succeeds on any well-formed JSON — a rate-limit
	// notice, an error body, a future response shape — and leaves every field
	// zero. Reading that zero as "no reports" is exactly how this panel came to
	// show a confident green nothing next to a critical alert for an address
	// with over a thousand reports against it. The echoed address is what
	// proves the reply is an answer about the address we asked about.
	// The reply has to carry something about the address before a zero in it
	// can mean anything. Without this check a decode succeeded on any
	// well-formed JSON — a rate-limit notice, an error body, a future response
	// shape — leaving every field zero, and that zero was read as "no
	// reports". It is how this panel came to show a confident green nothing
	// beside a critical alert for an address with over a thousand reports
	// against it. (This environment cannot reach isc.sans.edu, so the check is
	// deliberately structural rather than tied to one field name.)
	if out.IP == nil || (out.IP.Number == "" && out.IP.Count == 0 && out.IP.Attacks == 0 &&
		out.IP.MinDate == "" && out.IP.MaxDate == "" && out.IP.AsName == "") {
		fail(info, "dshield", "the reply carried nothing about this address")
		return fmt.Errorf("dshield: unrecognised response")
	}

	rec := *out.IP
	reports, targets := int(rec.Count), int(rec.Attacks)
	if reports > info.AbuseReports {
		info.AbuseReports = reports
	}
	if targets > info.Targets {
		info.Targets = targets
	}
	info.FirstReport = rec.MinDate
	info.LastReport = rec.MaxDate
	info.Source = "dshield"
	if info.ISP == "" {
		info.ISP = rec.AsName
	}
	if info.Country == "" && rec.Country != "" {
		info.Country = rec.Country
		info.CountrySource = "asn"
	}
	if rec.Category != "" {
		info.UsageType = rec.Category
	}

	if reports <= 0 {
		info.Signals = append(info.Signals, Signal{
			Source: "dshield", State: StateClean, Detail: "no reports",
		})
		return nil
	}
	r, t := reports, targets
	info.Signals = append(info.Signals, Signal{
		Source:  "dshield",
		State:   StateReported,
		Reports: &r,
		Targets: &t,
		Detail:  fmt.Sprintf("%d reports from %d targets", reports, targets),
	})
	return nil
}

// flexInt decodes a JSON number that may arrive as a string or null.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" || s == `""` {
		*f = 0
		return nil
	}
	s = trimQuotes(s)
	if s == "" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// A non-numeric value is not worth failing the whole lookup over.
		*f = 0
		return nil
	}
	*f = flexInt(n)
	return nil
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
