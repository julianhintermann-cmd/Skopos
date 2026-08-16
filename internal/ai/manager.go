package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Store is the persistence the manager needs. The SQLite store satisfies it.
type Store interface {
	AISetKey(sealed string) error
	AIKey() (string, bool, error)
	AIDeleteKey(ctx context.Context) error
	AISetMeta(v string) error
	AIMeta() (string, bool, error)
	AIDeleteMeta(ctx context.Context) error
}

// Sealer seals and opens the key. secret.Box satisfies it.
type Sealer interface {
	Seal(plaintext []byte) (string, error)
	Open(s string) ([]byte, error)
}

// settings is the non-secret half, stored beside the sealed key in the clear so
// the settings page can render state without unsealing anything.
type settings struct {
	Provider Provider `json:"provider"`
	Model    string   `json:"model"`
	// KeyTail is the last four characters of the key. It is not a masked
	// secret — four characters identify which key is installed without being
	// usable — and it exists so an operator with several keys can tell whether
	// the right one is in place.
	KeyTail string `json:"key_tail"`
	// VerifiedAt is when the provider last accepted the key.
	VerifiedAt time.Time `json:"verified_at"`
	// Enabled is the master switch. Off means no request is ever made, not
	// even a test one.
	Enabled bool `json:"enabled"`
}

// Status is what the UI may know. There is no field for the key, so no future
// edit can accidentally start returning it.
type Status struct {
	Configured bool       `json:"configured"`
	Enabled    bool       `json:"enabled"`
	Provider   Provider   `json:"provider,omitempty"`
	Model      string     `json:"model,omitempty"`
	KeyTail    string     `json:"key_tail,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Providers  []Info     `json:"providers"`
}

// Manager owns the sealed key and the settings beside it.
type Manager struct {
	store  Store
	box    Sealer
	client *Client
	clock  func() time.Time

	mu sync.Mutex
}

// NewManager builds a Manager.
func NewManager(st Store, box Sealer, c *Client, clock func() time.Time) *Manager {
	if clock == nil {
		clock = time.Now
	}
	if c == nil {
		c = NewClient()
	}
	return &Manager{store: st, box: box, client: c, clock: clock}
}

func (m *Manager) settings() (settings, bool, error) {
	raw, ok, err := m.store.AIMeta()
	if err != nil || !ok || raw == "" {
		return settings{}, false, err
	}
	var s settings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return settings{}, false, fmt.Errorf("ai: stored settings are unreadable: %w", err)
	}
	return s, true, nil
}

func (m *Manager) saveSettings(s settings) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return m.store.AISetMeta(string(raw))
}

// Status reports the current configuration, without the key.
func (m *Manager) Status() (Status, error) {
	out := Status{Providers: Catalog()}
	s, ok, err := m.settings()
	if err != nil {
		return out, err
	}
	_, hasKey, err := m.store.AIKey()
	if err != nil {
		return out, err
	}
	out.Configured = ok && hasKey
	if !out.Configured {
		return out, nil
	}
	out.Enabled = s.Enabled
	out.Provider = s.Provider
	out.Model = s.Model
	out.KeyTail = s.KeyTail
	if !s.VerifiedAt.IsZero() {
		v := s.VerifiedAt
		out.VerifiedAt = &v
	}
	return out, nil
}

// Connect verifies a key with the provider and, only if the provider accepts
// it, seals and stores it.
//
// The order is the point. An unverified key never reaches disk, so a typo
// cannot leave the installation in a state where the settings page claims a
// provider is configured and every later request fails.
func (m *Manager) Connect(ctx context.Context, p Provider, key, model string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !p.Valid() {
		return Status{}, errUnsupported(p)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return Status{}, fmt.Errorf("ai: no key given")
	}
	if model == "" {
		model = DefaultModel(p)
	}

	if _, err := m.client.Verify(ctx, p, key); err != nil {
		return Status{}, err
	}

	sealed, err := m.box.Seal([]byte(key))
	if err != nil {
		return Status{}, fmt.Errorf("ai: could not seal the key: %w", err)
	}
	if err := m.store.AISetKey(sealed); err != nil {
		return Status{}, err
	}
	if err := m.saveSettings(settings{
		Provider:   p,
		Model:      model,
		KeyTail:    tail(key),
		VerifiedAt: m.clock(),
		// Verifying a key is not the same as agreeing to send household data
		// to a third party. The operator turns it on separately, after the
		// disclosure.
		Enabled: false,
	}); err != nil {
		return Status{}, err
	}
	return m.Status()
}

// Disconnect deletes the sealed key and the settings beside it.
func (m *Manager) Disconnect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.store.AIDeleteKey(ctx); err != nil {
		return err
	}
	return m.store.AIDeleteMeta(ctx)
}

// SetEnabled flips the master switch. Off means no request leaves this machine.
func (m *Manager) SetEnabled(enabled bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok, err := m.settings()
	if err != nil {
		return Status{}, err
	}
	if !ok {
		return Status{}, ErrNotConfigured
	}
	s.Enabled = enabled
	if err := m.saveSettings(s); err != nil {
		return Status{}, err
	}
	return m.Status()
}

// SetModel changes the model without re-entering the key.
func (m *Manager) SetModel(model string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok, err := m.settings()
	if err != nil {
		return Status{}, err
	}
	if !ok {
		return Status{}, ErrNotConfigured
	}
	if model = strings.TrimSpace(model); model == "" {
		model = DefaultModel(s.Provider)
	}
	s.Model = model
	if err := m.saveSettings(s); err != nil {
		return Status{}, err
	}
	return m.Status()
}

// key unseals the stored key. This is the only place plaintext exists, and it
// exists as a local variable for the length of one request.
func (m *Manager) key() (Provider, string, string, error) {
	s, ok, err := m.settings()
	if err != nil {
		return "", "", "", err
	}
	if !ok {
		return "", "", "", ErrNotConfigured
	}
	if !s.Enabled {
		return "", "", "", ErrNotConfigured
	}
	sealed, has, err := m.store.AIKey()
	if err != nil {
		return "", "", "", err
	}
	if !has || sealed == "" {
		return "", "", "", ErrNotConfigured
	}
	plain, err := m.box.Open(sealed)
	if err != nil {
		return "", "", "", fmt.Errorf("ai: cannot decrypt the stored key: %w", err)
	}
	return s.Provider, string(plain), s.Model, nil
}

// Explain sends one prompt and returns the model's answer. It refuses when the
// integration is off, which is what makes "off" mean no packets rather than
// merely no button.
func (m *Manager) Explain(ctx context.Context, system, user string, maxTokens int) (string, error) {
	p, k, model, err := m.key()
	if err != nil {
		return "", err
	}
	return m.client.Complete(ctx, p, k, model, system, user, maxTokens)
}

// tail returns the last four characters of a key.
func tail(key string) string {
	r := []rune(key)
	if len(r) <= 4 {
		return string(r)
	}
	return string(r[len(r)-4:])
}
