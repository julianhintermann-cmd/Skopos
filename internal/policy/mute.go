package policy

import (
	"net/netip"
	"sync"
	"time"
)

// MuteRule is one suppression rule, mirrored from the store so the policy
// package stays free of a storage dependency.
type MuteRule struct {
	Detector string
	Prefix   netip.Prefix
	Port     int
	Expires  *time.Time
}

// Matches reports whether the rule covers a finding.
func (m MuteRule) Matches(detector string, source netip.Addr, port int, now time.Time) bool {
	if m.Expires != nil && now.After(*m.Expires) {
		return false
	}
	if m.Detector != "" && m.Detector != detector {
		return false
	}
	if m.Port != 0 && m.Port != port {
		return false
	}
	if m.Prefix.IsValid() && !m.Prefix.Contains(source.Unmap()) {
		return false
	}
	return true
}

// Muter holds the operator's suppression rules and answers the policy
// engine's "should I stay quiet about this?" question. Rules suppress the
// notification and the alert record — never the blocking decision, which
// stays with the policy: silencing a nuisance must not silently disarm the
// protection that goes with it.
type Muter struct {
	mu    sync.RWMutex
	rules []MuteRule
}

// NewMuter returns an empty muter.
func NewMuter() *Muter { return &Muter{} }

// Replace swaps the whole rule set.
func (m *Muter) Replace(rules []MuteRule) {
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

// Muted reports whether a finding is suppressed.
func (m *Muter) Muted(detector string, source netip.Addr, port int, now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.rules {
		if r.Matches(detector, source, port, now) {
			return true
		}
	}
	return false
}

// Len reports how many rules are loaded.
func (m *Muter) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}
