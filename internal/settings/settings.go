// Package settings holds the runtime-editable subset of the configuration.
// The YAML file stays the source of truth for everything structural — where
// to capture, where to store, how to authenticate — while the settings here
// are the knobs an operator reaches for while watching the dashboard:
// enforcement, thresholds, quiet hours, the allowlist. Changes are persisted
// as an override layer on top of the YAML and applied immediately, so arming
// the firewall no longer means editing a file and restarting a container.
package settings

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const overridesKey = "runtime_settings"

// KeyStore persists the override layer; the store's meta table satisfies it.
type KeyStore interface {
	GetMeta(key string) (string, bool, error)
	SetMeta(key, value string) error
}

// Thresholds are the port-scan trigger counts for one address class.
type Thresholds struct {
	Ports   int `json:"ports"`
	Targets int `json:"targets"`
}

// Portscan is the runtime-editable part of the port-scan detector.
type Portscan struct {
	Enabled  bool          `json:"enabled"`
	Window   time.Duration `json:"window"`
	External Thresholds    `json:"external"`
	Internal Thresholds    `json:"internal"`
	Block    bool          `json:"block"`
}

// Rate is the runtime-editable part of the connection-rate detector.
type Rate struct {
	Enabled             bool          `json:"enabled"`
	Window              time.Duration `json:"window"`
	MaxNewConnections   int           `json:"max_new_connections"`
	MaxPacketsPerSecond int           `json:"max_packets_per_second"`
	Block               bool          `json:"block"`
}

// QuietHours suppresses low-severity notifications overnight.
type QuietHours struct {
	Enabled     bool   `json:"enabled"`
	FromHour    int    `json:"from_hour"`
	FromMinute  int    `json:"from_minute"`
	ToHour      int    `json:"to_hour"`
	ToMinute    int    `json:"to_minute"`
	MinSeverity string `json:"min_severity"`
}

// Runtime is the full editable set. Every field has a value at all times:
// the YAML supplies the baseline, overrides replace individual fields.
type Runtime struct {
	Enforcement string        `json:"enforcement"`
	BlockTTL    time.Duration `json:"block_ttl"`
	Allowlist   []string      `json:"allowlist"`
	Cooldown    time.Duration `json:"cooldown"`
	QuietHours  QuietHours    `json:"quiet_hours"`
	Portscan    Portscan      `json:"portscan"`
	Rate        Rate          `json:"rate"`
}

// ApplyError is one subsystem refusing a setting that has already been stored.
// Field is the settings path the operator can act on — "enforcement",
// "allowlist" — not the internal call that failed.
type ApplyError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ApplyResult is what the live subsystems made of a stored change.
//
// Storing a setting and putting it into effect are two separate events, and
// only the first one used to be reported: a kernel that refused to arm the
// firewall was logged and the endpoint still answered ok, so the operator was
// told the network was protected while nothing was being dropped. Subscribers
// run synchronously inside Update, so the second event is already known by the
// time the caller gets its response — this is how it travels back to it.
type ApplyResult struct {
	Errors []ApplyError `json:"errors,omitempty"`
}

// OK reports whether every subsystem took the change.
func (r ApplyResult) OK() bool { return len(r.Errors) == 0 }

// Fail records one subsystem's refusal against the settings field behind it.
// A nil error records nothing, so callers need no branch of their own.
func (r *ApplyResult) Fail(field string, err error) {
	if err == nil {
		return
	}
	r.Errors = append(r.Errors, ApplyError{Field: field, Message: err.Error()})
}

// Manager owns the effective settings and notifies subscribers on change.
type Manager struct {
	ks   KeyStore
	base Runtime

	mu        sync.RWMutex
	current   Runtime
	overrides map[string]json.RawMessage
	subs      []func(Runtime) ApplyResult
}

// New loads any stored overrides and layers them onto the YAML baseline.
func New(ks KeyStore, base Runtime) (*Manager, error) {
	m := &Manager{ks: ks, base: base, current: base, overrides: map[string]json.RawMessage{}}
	raw, ok, err := ks.GetMeta(overridesKey)
	if err != nil {
		return nil, err
	}
	if ok && raw != "" {
		if err := json.Unmarshal([]byte(raw), &m.overrides); err != nil {
			// Corrupt overrides must not stop the service: fall back to the
			// YAML, which is always valid.
			m.overrides = map[string]json.RawMessage{}
		}
	}
	m.current = m.applyOverrides()
	return m, nil
}

// Current returns the effective settings.
func (m *Manager) Current() Runtime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Overridden lists the fields the operator has changed away from the YAML,
// so the UI can show what is no longer coming from the file.
func (m *Manager) Overridden() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.overrides))
	for k := range m.overrides {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Base returns the YAML baseline, so the UI can offer "reset to file".
func (m *Manager) Base() Runtime { return m.base }

// OnChange registers a subscriber with nothing to report back — an auditor, a
// logger. Called synchronously on every update, in registration order, with
// the new effective settings.
func (m *Manager) OnChange(f func(Runtime)) {
	m.OnApply(func(r Runtime) ApplyResult { f(r); return ApplyResult{} })
}

// OnApply registers a subscriber that says what it managed to do. Every
// subscriber's result is merged into the value Update and Reset return, so the
// endpoint that requested the change can answer with the outcome instead of
// with the intent it just persisted. Same contract as OnChange otherwise:
// synchronous, in registration order.
func (m *Manager) OnApply(f func(Runtime) ApplyResult) {
	m.mu.Lock()
	m.subs = append(m.subs, f)
	m.mu.Unlock()
}

// Update applies a patch of field paths (e.g. "enforcement",
// "portscan.external.ports") to the override layer, validates the result,
// persists it and notifies subscribers. It is all-or-nothing: an invalid
// patch changes nothing.
//
// The error means the patch was refused and nothing was stored. The
// ApplyResult means it was stored and says what the subsystems then did with
// it; the two are separate answers because "we wrote it down" and "it is in
// effect" are separate facts.
func (m *Manager) Update(patch map[string]json.RawMessage) (ApplyResult, error) {
	m.mu.Lock()
	next := make(map[string]json.RawMessage, len(m.overrides)+len(patch))
	for k, v := range m.overrides {
		next[k] = v
	}
	for k, v := range patch {
		if !editable[k] {
			m.mu.Unlock()
			return ApplyResult{}, fmt.Errorf("settings: %q is not editable at runtime", k)
		}
		next[k] = v
	}
	candidate, err := applyTo(m.base, next)
	if err != nil {
		m.mu.Unlock()
		return ApplyResult{}, err
	}
	if err := Validate(candidate); err != nil {
		m.mu.Unlock()
		return ApplyResult{}, err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		m.mu.Unlock()
		return ApplyResult{}, err
	}
	if err := m.ks.SetMeta(overridesKey, string(raw)); err != nil {
		m.mu.Unlock()
		return ApplyResult{}, err
	}
	m.overrides = next
	m.current = candidate
	subs := append([]func(Runtime) ApplyResult{}, m.subs...)
	m.mu.Unlock()

	return notify(subs, candidate), nil
}

// Reset drops every override, returning to the YAML baseline. It reports the
// apply outcome exactly as Update does: going back to the file is a kernel
// change too, and it can be refused the same way.
func (m *Manager) Reset() (ApplyResult, error) {
	m.mu.Lock()
	if err := m.ks.SetMeta(overridesKey, ""); err != nil {
		m.mu.Unlock()
		return ApplyResult{}, err
	}
	m.overrides = map[string]json.RawMessage{}
	m.current = m.base
	subs := append([]func(Runtime) ApplyResult{}, m.subs...)
	base := m.base
	m.mu.Unlock()

	return notify(subs, base), nil
}

// notify runs every subscriber and collects what each one reported. All of
// them run even after one fails: the subsystems are independent, and stopping
// at the first refusal would leave the rest of the settings unapplied with
// nothing said about them.
func notify(subs []func(Runtime) ApplyResult, r Runtime) ApplyResult {
	var out ApplyResult
	for _, f := range subs {
		out.Errors = append(out.Errors, f(r).Errors...)
	}
	return out
}

// applyOverrides layers the stored overrides onto the baseline; callers hold
// the lock. An override that no longer parses is ignored rather than fatal.
func (m *Manager) applyOverrides() Runtime {
	out, err := applyTo(m.base, m.overrides)
	if err != nil {
		return m.base
	}
	return out
}

// editable is the allowlist of override paths. Anything outside it is
// refused, so a typo cannot silently do nothing and an unexpected key cannot
// reach the decoder.
var editable = map[string]bool{
	"enforcement":              true,
	"block_ttl":                true,
	"allowlist":                true,
	"cooldown":                 true,
	"quiet_hours":              true,
	"portscan.enabled":         true,
	"portscan.window":          true,
	"portscan.external":        true,
	"portscan.internal":        true,
	"portscan.block":           true,
	"rate.enabled":             true,
	"rate.window":              true,
	"rate.max_new_connections": true,
	"rate.max_packets_per_sec": true,
	"rate.block":               true,
}

// applyTo decodes each override onto a copy of base.
func applyTo(base Runtime, overrides map[string]json.RawMessage) (Runtime, error) {
	out := base
	out.Allowlist = append([]string(nil), base.Allowlist...)

	for path, raw := range overrides {
		var err error
		switch path {
		case "enforcement":
			err = json.Unmarshal(raw, &out.Enforcement)
		case "block_ttl":
			err = unmarshalDuration(raw, &out.BlockTTL)
		case "allowlist":
			err = json.Unmarshal(raw, &out.Allowlist)
		case "cooldown":
			err = unmarshalDuration(raw, &out.Cooldown)
		case "quiet_hours":
			err = json.Unmarshal(raw, &out.QuietHours)
		case "portscan.enabled":
			err = json.Unmarshal(raw, &out.Portscan.Enabled)
		case "portscan.window":
			err = unmarshalDuration(raw, &out.Portscan.Window)
		case "portscan.external":
			err = json.Unmarshal(raw, &out.Portscan.External)
		case "portscan.internal":
			err = json.Unmarshal(raw, &out.Portscan.Internal)
		case "portscan.block":
			err = json.Unmarshal(raw, &out.Portscan.Block)
		case "rate.enabled":
			err = json.Unmarshal(raw, &out.Rate.Enabled)
		case "rate.window":
			err = unmarshalDuration(raw, &out.Rate.Window)
		case "rate.max_new_connections":
			err = json.Unmarshal(raw, &out.Rate.MaxNewConnections)
		case "rate.max_packets_per_sec":
			err = json.Unmarshal(raw, &out.Rate.MaxPacketsPerSecond)
		case "rate.block":
			err = json.Unmarshal(raw, &out.Rate.Block)
		default:
			continue // unknown key from an older version: ignore
		}
		if err != nil {
			return base, fmt.Errorf("settings: %s: %w", path, err)
		}
	}
	return out, nil
}

// unmarshalDuration accepts both a duration string ("24h") and a raw
// nanosecond count, so the UI can send whichever is natural.
func unmarshalDuration(raw json.RawMessage, dst *time.Duration) error {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return err
		}
		*dst = d
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return fmt.Errorf("expected a duration string or nanoseconds")
	}
	*dst = time.Duration(n)
	return nil
}

// Validate rejects settings that would break the service or lock the
// operator out. It runs before anything is persisted.
func Validate(r Runtime) error {
	switch r.Enforcement {
	case "observe", "enforce":
	default:
		return fmt.Errorf("settings: enforcement must be observe or enforce, got %q", r.Enforcement)
	}
	if r.BlockTTL < 0 || r.Cooldown < 0 {
		return fmt.Errorf("settings: durations must not be negative")
	}
	if r.Portscan.Window <= 0 || r.Rate.Window <= 0 {
		return fmt.Errorf("settings: detector windows must be positive")
	}
	if r.Portscan.External.Ports <= 0 || r.Portscan.External.Targets <= 0 ||
		r.Portscan.Internal.Ports <= 0 || r.Portscan.Internal.Targets <= 0 {
		return fmt.Errorf("settings: port-scan thresholds must be positive")
	}
	if r.Rate.MaxNewConnections <= 0 || r.Rate.MaxPacketsPerSecond <= 0 {
		return fmt.Errorf("settings: rate limits must be positive")
	}
	for _, e := range r.Allowlist {
		if _, err := ParsePrefix(e); err != nil {
			return fmt.Errorf("settings: allowlist entry %q: %w", e, err)
		}
	}
	switch r.QuietHours.MinSeverity {
	case "", "info", "warning", "critical":
	default:
		return fmt.Errorf("settings: quiet-hours min_severity must be info, warning or critical")
	}
	if !validClock(r.QuietHours.FromHour, r.QuietHours.FromMinute) ||
		!validClock(r.QuietHours.ToHour, r.QuietHours.ToMinute) {
		return fmt.Errorf("settings: quiet-hours times must be valid clock times")
	}
	return nil
}

func validClock(h, m int) bool { return h >= 0 && h < 24 && m >= 0 && m < 60 }

// ParsePrefix accepts both a bare address and a CIDR.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an address or CIDR")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
