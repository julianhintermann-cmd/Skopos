// Package geoip resolves IP addresses to countries using the DB-IP "IP to
// Country Lite" database (CC BY 4.0), downloaded at runtime like the blocklist
// feeds — nothing geographic ships inside the image. The database refreshes
// monthly; lookups are local, so no address ever leaves the machine.
package geoip

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Provider is what the rest of Skopos consumes: a country lookup that may not
// be ready yet (the first download can still be in flight).
type Provider interface {
	// Lookup returns the ISO 3166-1 alpha-2 code for addr.
	Lookup(addr netip.Addr) (string, bool)
	// Available reports whether lookups can succeed at all.
	Available() bool
}

// dbURLTemplate is the DB-IP Lite monthly file. The %s is YYYY-MM.
const dbURLTemplate = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"

// Manager downloads, refreshes and serves the database. Safe for concurrent
// use; the reader swaps atomically under the lock.
type Manager struct {
	HTTP *http.Client
	// URLTemplate is overridable for tests (must contain one %s for YYYY-MM).
	URLTemplate string

	dir   string
	clock func() time.Time
	log   func(string, ...any)

	mu     sync.RWMutex
	reader *maxminddb.Reader
}

// NewManager creates a Manager that caches the database under dir.
func NewManager(dir string, clock func() time.Time) *Manager {
	if clock == nil {
		clock = time.Now
	}
	return &Manager{
		HTTP:        &http.Client{Timeout: 2 * time.Minute},
		URLTemplate: dbURLTemplate,
		dir:         dir,
		clock:       clock,
		log:         func(string, ...any) {},
	}
}

// SetLogger installs a logging callback.
func (m *Manager) SetLogger(f func(string, ...any)) { m.log = f }

func (m *Manager) dbPath() string { return filepath.Join(m.dir, "dbip-country.mmdb") }

// Start loads a cached database if present, then keeps it fresh until ctx is
// cancelled. It returns immediately; the first download happens in the
// background so startup never blocks on the network.
func (m *Manager) Start(ctx context.Context) {
	if err := m.load(); err == nil {
		m.log("geoip: loaded cached database")
	}
	go m.refreshLoop(ctx)
}

func (m *Manager) refreshLoop(ctx context.Context) {
	// Retry quickly until the first database is in place, then check daily
	// (the file only changes monthly).
	for {
		wait := 24 * time.Hour
		if !m.Available() {
			wait = 15 * time.Minute
		}
		if err := m.refresh(ctx); err != nil && ctx.Err() == nil {
			m.log("geoip: refresh failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refresh downloads the current month's database when the cached copy is
// missing or stale, and swaps it in atomically.
func (m *Manager) refresh(ctx context.Context) error {
	month := m.clock().UTC().Format("2006-01")
	if m.Available() && m.cachedMonth() == month {
		return nil
	}

	url := fmt.Sprintf(m.URLTemplate, month)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip: %s returned %s", url, resp.Status)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("geoip: not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	tmp := m.dbPath() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(gz, 256<<20)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Validate before swapping: a truncated download must never replace a
	// working database.
	probe, err := maxminddb.Open(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("geoip: downloaded file is not a valid mmdb: %w", err)
	}
	_ = probe.Close()

	if err := os.Rename(tmp, m.dbPath()); err != nil {
		return err
	}
	if err := os.WriteFile(m.monthPath(), []byte(month), 0o644); err != nil {
		m.log("geoip: recording month: %v", err)
	}
	if err := m.load(); err != nil {
		return err
	}
	m.log("geoip: database updated (%s)", month)
	return nil
}

func (m *Manager) monthPath() string { return m.dbPath() + ".month" }

func (m *Manager) cachedMonth() string {
	b, err := os.ReadFile(m.monthPath())
	if err != nil {
		return ""
	}
	return string(b)
}

// load (re)opens the on-disk database.
func (m *Manager) load() error {
	r, err := maxminddb.Open(m.dbPath())
	if err != nil {
		return err
	}
	m.mu.Lock()
	old := m.reader
	m.reader = r
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Available implements Provider.
func (m *Manager) Available() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.reader != nil
}

// Lookup implements Provider.
func (m *Manager) Lookup(addr netip.Addr) (string, bool) {
	m.mu.RLock()
	r := m.reader
	m.mu.RUnlock()
	if r == nil || !addr.IsValid() {
		return "", false
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.Lookup(addr.AsSlice(), &rec); err != nil || rec.Country.ISOCode == "" {
		return "", false
	}
	return rec.Country.ISOCode, true
}
