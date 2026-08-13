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

// listedScore is what "this address is on a blocklist you subscribe to"
// is worth on the 0–100 scale. The built-in lists (FireHOL Level 1, Spamhaus
// DROP) are conservative and slow to add an address, so a match is strong
// evidence — and it is evidence Skopos already had in memory while the card
// was reporting nothing.
const listedScore = 70

// userAgent identifies Skopos to DShield, which asks API users to be
// identifiable rather than anonymous.
const userAgent = "Skopos (+https://github.com/julianhintermann-cmd/skopos)"

// Signal is one source's verdict, kept separate so the card can show who said
// what instead of a single number nobody can check.
type Signal struct {
	Source string `json:"source"`
	// Score is this source's 0–100 reading, or nil when it had no data. A
	// source that answered "I have never seen this address" is not the same
	// as a source that answered zero.
	Score  *int   `json:"score,omitempty"`
	Detail string `json:"detail"`
}

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
	// AbuseScore is the highest 0–100 reading any source returned; nil when
	// no source had data at all.
	AbuseScore   *int   `json:"abuse_score,omitempty"`
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
	// Listed reports whether the address is in one of the blocklists the
	// operator already subscribes to. Answered from memory, no request.
	Listed func(netip.Addr) bool

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
	dshieldOK := s.dshield(ctx, ip, &info) == nil
	blOK := s.blocklistDE(ctx, ip, &info) == nil
	if !rdapOK && !dshieldOK && !blOK && len(info.Signals) == 0 {
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
	if s.Listed(addr) {
		score := listedScore
		info.Signals = append(info.Signals, Signal{
			Source: "blocklists",
			Score:  &score,
			Detail: "on a blocklist you subscribe to",
		})
		return
	}
	info.Signals = append(info.Signals, Signal{
		Source: "blocklists",
		Detail: "not on your blocklists",
	})
}

// combine reduces the per-source readings to the single number the dashboard
// shows. The strongest reading wins rather than an average: one source with
// solid evidence should not be diluted by three that happen not to have heard
// of the address. When nobody had data the score stays nil, because "no
// reports" is an absence of evidence, not evidence of absence.
func (s *Service) combine(info *Info) {
	var best *int
	for _, sig := range info.Signals {
		if sig.Score == nil {
			continue
		}
		if best == nil || *sig.Score > *best {
			v := *sig.Score
			best = &v
		}
	}
	info.AbuseScore = best
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
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("blocklist.de: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}

	attacks, reports, ok := parseBlocklistDE(string(body))
	if !ok {
		return fmt.Errorf("blocklist.de: unrecognised response")
	}
	if reports <= 0 && attacks <= 0 {
		info.Signals = append(info.Signals, Signal{
			Source: "blocklist.de",
			Detail: "no reports",
		})
		return nil
	}
	score := blocklistDEScore(attacks, reports)
	info.Signals = append(info.Signals, Signal{
		Source: "blocklist.de",
		Score:  &score,
		Detail: fmt.Sprintf("%d reports, %d attacks", reports, attacks),
	})
	if reports > info.AbuseReports {
		info.AbuseReports = reports
	}
	return nil
}

// parseBlocklistDE reads the service's plain-text reply, which is a couple of
// "key: value" lines. Tolerant on purpose: an unfamiliar key is skipped
// rather than failing a lookup whose other sources answered fine.
func parseBlocklistDE(body string) (attacks, reports int, ok bool) {
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
			attacks, ok = n, true
		case "reports":
			reports, ok = n, true
		}
	}
	return attacks, reports, ok
}

// blocklistDEScore maps report volume onto the shared 0–100 scale. Its
// reports come from operators who saw the address attack them, so even a
// handful means something.
func blocklistDEScore(attacks, reports int) int {
	n := max(reports, attacks)
	switch {
	case n >= 500:
		return 95
	case n >= 100:
		return 85
	case n >= 20:
		return 70
	case n >= 5:
		return 55
	case n >= 1:
		return 35
	default:
		return 0
	}
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
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dshield: %s", resp.Status)
	}
	// DShield types loosely: counts arrive as numbers or strings, and unknown
	// addresses answer with nulls. flexInt absorbs all of it.
	var out struct {
		IP struct {
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

	rec := out.IP
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
		info.Signals = append(info.Signals, Signal{Source: "dshield", Detail: "no reports"})
		return nil
	}
	score := dshieldScore(reports, targets)
	info.Signals = append(info.Signals, Signal{
		Source: "dshield",
		Score:  &score,
		Detail: fmt.Sprintf("%d reports, %d targets", reports, targets),
	})
	return nil
}

// dshieldScore maps report volume onto the same 0–100 scale the dashboard
// already renders. Reports are logs submitted by sensors, targets are the
// distinct victims: an address hammering many networks scores higher than one
// noisy log from a single sensor.
func dshieldScore(reports, targets int) int {
	if reports <= 0 {
		return 0
	}
	score := 0
	switch {
	case reports >= 10000:
		score = 75
	case reports >= 1000:
		score = 60
	case reports >= 100:
		score = 45
	case reports >= 10:
		score = 30
	default:
		score = 15
	}
	switch {
	case targets >= 100:
		score += 25
	case targets >= 10:
		score += 15
	case targets >= 2:
		score += 5
	}
	return min(score, 100)
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
