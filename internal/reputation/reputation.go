// Package reputation answers "who is this address" for alerts and blocks:
// owner and country via RDAP (the registries' successor to WHOIS), and attack
// history via the SANS Internet Storm Center's DShield database. Both are
// free, need no account and no API key, so reputation works out of the box on
// a fresh install. Results are cached for a day.
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
	"sync"
	"time"
)

const (
	defaultRDAPBase    = "https://rdap.org"
	defaultDShieldBase = "https://isc.sans.edu"
	cacheTTL           = 24 * time.Hour
	maxBody            = 1 << 20
)

// userAgent identifies Skopos to DShield, which asks API users to be
// identifiable rather than anonymous.
const userAgent = "Skopos (+https://github.com/julianhintermann-cmd/skopos)"

// Info is everything Skopos knows about an external address.
type Info struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Country string `json:"country,omitempty"`
	// AbuseScore is a 0–100 confidence derived from DShield's attack
	// history; nil when the address is unknown to it. The field name is
	// kept so existing dashboards and API consumers keep working.
	AbuseScore   *int   `json:"abuse_score,omitempty"`
	AbuseReports int    `json:"abuse_reports,omitempty"`
	ISP          string `json:"isp,omitempty"`
	UsageType    string `json:"usage_type,omitempty"`
	// Targets is how many distinct victims reported this address.
	Targets int `json:"targets,omitempty"`
	// FirstReport / LastReport bound the observed activity.
	FirstReport string    `json:"first_report,omitempty"`
	LastReport  string    `json:"last_report,omitempty"`
	Source      string    `json:"source,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// Service performs and caches lookups.
type Service struct {
	HTTP        *http.Client
	RDAPBase    string
	DShieldBase string

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
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		RDAPBase:    defaultRDAPBase,
		DShieldBase: defaultDShieldBase,
		clock:       clock,
		cache:       map[string]cacheEntry{},
	}
}

// Lookup resolves one address, serving from cache when fresh. The two sources
// degrade independently — whatever answered is returned.
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
	rdapOK := s.rdap(ctx, ip, &info) == nil
	dshieldOK := s.dshield(ctx, ip, &info) == nil
	if !rdapOK && !dshieldOK {
		return info, fmt.Errorf("reputation: all sources failed for %s", ip)
	}

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
	if info.Country == "" {
		info.Country = rec.Country
	}
	return nil
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
	score := dshieldScore(int(rec.Count), int(rec.Attacks))
	info.AbuseScore = &score
	info.AbuseReports = int(rec.Count)
	info.Targets = int(rec.Attacks)
	info.FirstReport = rec.MinDate
	info.LastReport = rec.MaxDate
	info.Source = "dshield"
	if info.ISP == "" {
		info.ISP = rec.AsName
	}
	if info.Country == "" {
		info.Country = rec.Country
	}
	if rec.Category != "" {
		info.UsageType = rec.Category
	}
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
