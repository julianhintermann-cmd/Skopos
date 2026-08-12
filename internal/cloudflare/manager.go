package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/secret"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// cfMetaKey holds non-secret token metadata (id, expiry) so status can be
// reported without a network round-trip on every poll.
const cfMetaKey = "cloudflare_meta"

// tokenMeta is the small, non-secret descriptor persisted alongside the sealed
// token.
type tokenMeta struct {
	TokenID   string `json:"token_id"`
	ExpiresOn string `json:"expires_on"`
}

// ZoneView is the API-facing shape of a connected zone.
type ZoneView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Monitored bool   `json:"monitored"`
}

// Status is the connection state returned to the UI. It never carries the token.
type Status struct {
	Connected bool       `json:"connected"`
	TokenID   string     `json:"token_id,omitempty"`
	ExpiresOn string     `json:"expires_on,omitempty"`
	Zones     []ZoneView `json:"zones"`
}

// Manager owns the Cloudflare connection: the sealed token, the persisted zone
// list, and a short analytics cache. It is safe for concurrent use.
type Manager struct {
	store  *store.Store
	box    *secret.Box
	client *Client
	now    func() time.Time
	ttl    time.Duration // analytics cache TTL

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	at     time.Time
	series AnalyticsSeries
}

// NewManager wires a Manager. clock may be nil (defaults to time.Now).
func NewManager(st *store.Store, box *secret.Box, client *Client, clock func() time.Time) *Manager {
	if clock == nil {
		clock = time.Now
	}
	if client == nil {
		client = NewClient()
	}
	return &Manager{
		store:  st,
		box:    box,
		client: client,
		now:    clock,
		ttl:    60 * time.Second,
		cache:  map[string]cacheEntry{},
	}
}

// token decrypts and returns the stored token, or ("", false) if not connected.
func (m *Manager) token() (string, bool, error) {
	sealed, ok, err := m.store.CFToken()
	if err != nil || !ok || sealed == "" {
		return "", false, err
	}
	plain, err := m.box.Open(sealed)
	if err != nil {
		return "", false, fmt.Errorf("cloudflare: cannot decrypt stored token: %w", err)
	}
	return string(plain), true, nil
}

// Connected reports whether a token is stored.
func (m *Manager) Connected() bool {
	_, ok, _ := m.token()
	return ok
}

// Status reports the connection state and connected zones without a network
// call.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	_, ok, err := m.token()
	if err != nil {
		return Status{}, err
	}
	if !ok {
		return Status{Connected: false, Zones: []ZoneView{}}, nil
	}
	zones, err := m.zoneViews(ctx)
	if err != nil {
		return Status{}, err
	}
	st := Status{Connected: true, Zones: zones}
	if raw, ok, _ := m.store.GetMeta(cfMetaKey); ok {
		var meta tokenMeta
		if json.Unmarshal([]byte(raw), &meta) == nil {
			st.TokenID = meta.TokenID
			st.ExpiresOn = meta.ExpiresOn
		}
	}
	return st, nil
}

// Connect verifies the token, seals and stores it, refreshes the zone list, and
// returns the resulting status. A blank or inactive token is rejected before
// anything is stored.
func (m *Manager) Connect(ctx context.Context, token string) (Status, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Status{}, fmt.Errorf("cloudflare: empty token")
	}

	ts, err := m.client.VerifyToken(ctx, token)
	if err != nil {
		return Status{}, err
	}
	if !ts.Active() {
		return Status{}, fmt.Errorf("cloudflare: token is %s, not active", ts.Status)
	}

	zones, err := m.client.ListZones(ctx, token)
	if err != nil {
		return Status{}, err
	}

	sealed, err := m.box.Seal([]byte(token))
	if err != nil {
		return Status{}, err
	}
	if err := m.store.CFSetToken(sealed); err != nil {
		return Status{}, err
	}
	meta, _ := json.Marshal(tokenMeta{TokenID: ts.ID, ExpiresOn: ts.ExpiresOn})
	_ = m.store.SetMeta(cfMetaKey, string(meta))

	if err := m.syncZones(ctx, zones); err != nil {
		return Status{}, err
	}
	m.flushCache()
	return m.Status(ctx)
}

// Disconnect wipes the token and connected zones.
func (m *Manager) Disconnect(ctx context.Context) error {
	if err := m.store.CFDeleteToken(ctx); err != nil {
		return err
	}
	if err := m.store.CFClearZones(ctx); err != nil {
		return err
	}
	_ = m.store.SetMeta(cfMetaKey, "") // best-effort clear of token metadata
	m.flushCache()
	return nil
}

// SetMonitored toggles whether a zone's traffic is monitored.
func (m *Manager) SetMonitored(ctx context.Context, zoneID string, on bool) error {
	return m.store.CFSetZoneMonitored(ctx, zoneID, on)
}

// Analytics returns per-hour request traffic for a zone over the trailing
// window, cached briefly so repeated dashboard polls do not hammer the API.
func (m *Manager) Analytics(ctx context.Context, zoneID string, window time.Duration) (AnalyticsSeries, error) {
	token, ok, err := m.token()
	if err != nil {
		return AnalyticsSeries{}, err
	}
	if !ok {
		return AnalyticsSeries{}, fmt.Errorf("cloudflare: not connected")
	}
	if window <= 0 {
		window = 24 * time.Hour
	}

	key := fmt.Sprintf("%s|%s", zoneID, window)
	now := m.now()
	m.mu.Lock()
	if e, ok := m.cache[key]; ok && now.Sub(e.at) < m.ttl {
		series := e.series
		m.mu.Unlock()
		return series, nil
	}
	m.mu.Unlock()

	series, err := m.client.Analytics(ctx, token, zoneID, now.Add(-window), now)
	if err != nil {
		return AnalyticsSeries{}, err
	}

	m.mu.Lock()
	m.cache[key] = cacheEntry{at: now, series: series}
	m.mu.Unlock()
	return series, nil
}

// MonitoredZones returns the ids of zones the operator is monitoring.
func (m *Manager) MonitoredZones(ctx context.Context) ([]string, error) {
	zones, err := m.store.CFListZones(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, z := range zones {
		if z.Monitored {
			ids = append(ids, z.ID)
		}
	}
	return ids, nil
}

// syncZones upserts the fetched zones and prunes ones the token can no longer
// see, preserving monitored flags for zones that remain.
func (m *Manager) syncZones(ctx context.Context, zones []Zone) error {
	keep := make(map[string]bool, len(zones))
	for _, z := range zones {
		keep[z.ID] = true
		if err := m.store.CFUpsertZone(ctx, model.CFZone{
			ID: z.ID, Name: z.Name, Status: z.Status, Monitored: true,
		}); err != nil {
			return err
		}
	}
	return m.store.CFPruneZonesExcept(ctx, keep)
}

func (m *Manager) zoneViews(ctx context.Context) ([]ZoneView, error) {
	zones, err := m.store.CFListZones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ZoneView, 0, len(zones))
	for _, z := range zones {
		out = append(out, ZoneView{ID: z.ID, Name: z.Name, Status: z.Status, Monitored: z.Monitored})
	}
	return out, nil
}

func (m *Manager) flushCache() {
	m.mu.Lock()
	m.cache = map[string]cacheEntry{}
	m.mu.Unlock()
}
