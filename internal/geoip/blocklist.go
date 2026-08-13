package geoip

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// KeyStore persists the blocked-country list; the store's meta table
// satisfies it.
type KeyStore interface {
	GetMeta(key string) (string, bool, error)
	SetMeta(key, value string) error
}

const blocklistKey = "geoip_blocked_countries"

var isoCode = regexp.MustCompile(`^[A-Z]{2}$`)

// Blocklist is the operator's set of blocked countries, persisted in the
// store and served lock-free enough for the packet path.
type Blocklist struct {
	ks KeyStore

	mu       sync.RWMutex
	codes    map[string]bool
	onChange func()
}

// NewBlocklist loads the persisted list (an empty one on first run).
func NewBlocklist(ks KeyStore) (*Blocklist, error) {
	b := &Blocklist{ks: ks, codes: map[string]bool{}}
	raw, ok, err := ks.GetMeta(blocklistKey)
	if err != nil {
		return nil, err
	}
	if ok && raw != "" {
		var codes []string
		if err := json.Unmarshal([]byte(raw), &codes); err == nil {
			for _, c := range codes {
				b.codes[c] = true
			}
		}
	}
	return b, nil
}

// Contains reports whether the country is blocked. Hot path — called per
// inbound packet by the detector.
func (b *Blocklist) Contains(code string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.codes[code]
}

// Empty reports whether no countries are blocked (lets the detector bail
// before doing a lookup at all).
func (b *Blocklist) Empty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.codes) == 0
}

// Countries returns the blocked codes, sorted.
func (b *Blocklist) Countries() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.codes))
	for c := range b.codes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Set validates, persists and installs a new list. Codes are upper-cased;
// anything that is not two ASCII letters is rejected.
func (b *Blocklist) Set(codes []string) error {
	clean := map[string]bool{}
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if !isoCode.MatchString(c) {
			return fmt.Errorf("geoip: %q is not an ISO 3166-1 alpha-2 code", c)
		}
		clean[c] = true
	}
	list := make([]string, 0, len(clean))
	for c := range clean {
		list = append(list, c)
	}
	sort.Strings(list)
	raw, _ := json.Marshal(list)
	if err := b.ks.SetMeta(blocklistKey, string(raw)); err != nil {
		return err
	}
	b.mu.Lock()
	b.codes = clean
	notify := b.onChange
	b.mu.Unlock()
	if notify != nil {
		notify()
	}
	return nil
}

// SetOnChange registers a callback invoked after every successful Set. The
// firewall's country enforcer hooks in here so the kernel's preventive sets
// follow the list without polling.
func (b *Blocklist) SetOnChange(f func()) {
	b.mu.Lock()
	b.onChange = f
	b.mu.Unlock()
}
