// Package reputation answers "who is this address" for alerts and blocks:
// owner and country via RDAP (the registries' successor to WHOIS — free, no
// key), plus an optional AbuseIPDB confidence score when the operator has
// connected an API key. Results are cached; the key is sealed at rest like
// every other secret.
package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/secret"
)

const (
	defaultRDAPBase  = "https://rdap.org"
	defaultAbuseBase = "https://api.abuseipdb.com"
	abuseKeyMeta     = "abuseipdb_key"
	cacheTTL         = 24 * time.Hour
	maxBody          = 1 << 20
)

// Info is everything Skopos knows about an external address.
type Info struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Country string `json:"country,omitempty"`
	// AbuseScore is AbuseIPDB's 0–100 confidence; nil when no key is set.
	AbuseScore   *int      `json:"abuse_score,omitempty"`
	AbuseReports int       `json:"abuse_reports,omitempty"`
	ISP          string    `json:"isp,omitempty"`
	UsageType    string    `json:"usage_type,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
}

// KeyStore persists the sealed AbuseIPDB key.
type KeyStore interface {
	GetMeta(key string) (string, bool, error)
	SetMeta(key, value string) error
}

// Service performs and caches lookups.
type Service struct {
	HTTP      *http.Client
	RDAPBase  string
	AbuseBase string

	ks    KeyStore
	box   *secret.Box
	clock func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	at   time.Time
	info Info
}

// New builds a Service.
func New(ks KeyStore, box *secret.Box, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		HTTP:      &http.Client{Timeout: 15 * time.Second},
		RDAPBase:  defaultRDAPBase,
		AbuseBase: defaultAbuseBase,
		ks:        ks,
		box:       box,
		clock:     clock,
		cache:     map[string]cacheEntry{},
	}
}

// HasAbuseKey reports whether an AbuseIPDB key is configured.
func (s *Service) HasAbuseKey() bool {
	v, ok, err := s.ks.GetMeta(abuseKeyMeta)
	return err == nil && ok && v != ""
}

// SetAbuseKey verifies the key against AbuseIPDB, then seals and stores it.
func (s *Service) SetAbuseKey(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("reputation: empty key")
	}
	if _, err := s.abuseCheck(ctx, key, "8.8.8.8"); err != nil {
		return fmt.Errorf("reputation: key rejected: %w", err)
	}
	sealed, err := s.box.Seal([]byte(key))
	if err != nil {
		return err
	}
	s.flush()
	return s.ks.SetMeta(abuseKeyMeta, sealed)
}

// DeleteAbuseKey removes the stored key.
func (s *Service) DeleteAbuseKey() error {
	s.flush()
	return s.ks.SetMeta(abuseKeyMeta, "")
}

func (s *Service) abuseKey() string {
	sealed, ok, err := s.ks.GetMeta(abuseKeyMeta)
	if err != nil || !ok || sealed == "" {
		return ""
	}
	plain, err := s.box.Open(sealed)
	if err != nil {
		return ""
	}
	return string(plain)
}

// Lookup resolves one address, serving from cache when fresh. RDAP and
// AbuseIPDB failures degrade independently — whatever answered is returned.
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
	abuseOK := true
	if key := s.abuseKey(); key != "" {
		abuseOK = s.abuse(ctx, key, ip, &info) == nil
	}
	if !rdapOK && !abuseOK {
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

func (s *Service) flush() {
	s.mu.Lock()
	s.cache = map[string]cacheEntry{}
	s.mu.Unlock()
}

// rdap fills owner and country from the registry's RDAP record.
func (s *Service) rdap(ctx context.Context, ip string, info *Info) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.RDAPBase+"/ip/"+url.PathEscape(ip), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")
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

// abuse fills the AbuseIPDB fields.
func (s *Service) abuse(ctx context.Context, key, ip string, info *Info) error {
	rec, err := s.abuseCheck(ctx, key, ip)
	if err != nil {
		return err
	}
	info.AbuseScore = &rec.Score
	info.AbuseReports = rec.Reports
	info.ISP = rec.ISP
	info.UsageType = rec.UsageType
	if info.Country == "" {
		info.Country = rec.Country
	}
	return nil
}

type abuseRecord struct {
	Score     int
	Reports   int
	ISP       string
	UsageType string
	Country   string
}

func (s *Service) abuseCheck(ctx context.Context, key, ip string) (abuseRecord, error) {
	u := fmt.Sprintf("%s/api/v2/check?ipAddress=%s&maxAgeInDays=90", s.AbuseBase, url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return abuseRecord{}, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return abuseRecord{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return abuseRecord{}, fmt.Errorf("abuseipdb rejected the key (%s)", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return abuseRecord{}, fmt.Errorf("abuseipdb: %s", resp.Status)
	}
	var out struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			ISP                  string `json:"isp"`
			UsageType            string `json:"usageType"`
			CountryCode          string `json:"countryCode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return abuseRecord{}, err
	}
	return abuseRecord{
		Score:     out.Data.AbuseConfidenceScore,
		Reports:   out.Data.TotalReports,
		ISP:       out.Data.ISP,
		UsageType: out.Data.UsageType,
		Country:   out.Data.CountryCode,
	}, nil
}
