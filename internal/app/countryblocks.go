package app

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/geoip"
	"github.com/julianhintermann-cmd/skopos/internal/netset"
)

// countryEnforcer keeps the kernel's preventive country sets in sync with the
// blocked-country list and the GeoIP database: it walks the database for the
// listed countries' prefixes and hands them to the firewall, so traffic from
// those countries is dropped before any service sees it — instead of only
// after a source has already appeared once.
type countryEnforcer struct {
	provider geoip.Provider
	list     *geoip.Blocklist
	fw       *firewall.Service
	logf     func(string, ...any)
	warnf    func(string, ...any)
	// enforceActive mirrors the startup enforcement decision; Covered must
	// answer false in observe mode, where the kernel drops nothing.
	enforceActive bool

	trigger chan struct{}

	// set mirrors the prefixes last handed to the kernel, so the reactive
	// detector and the live view can ask "is this source already dropped?".
	set atomic.Pointer[netset.Set]

	mu     sync.Mutex
	counts map[string]int
	loaded bool
}

func newCountryEnforcer(provider geoip.Provider, list *geoip.Blocklist, fw *firewall.Service, enforceActive bool, logf, warnf func(string, ...any)) *countryEnforcer {
	ce := &countryEnforcer{
		provider:      provider,
		list:          list,
		fw:            fw,
		logf:          logf,
		warnf:         warnf,
		enforceActive: enforceActive,
		trigger:       make(chan struct{}, 1),
		counts:        map[string]int{},
	}
	empty := netset.New()
	empty.Build()
	ce.set.Store(empty)
	list.SetOnChange(ce.kick)
	return ce
}

// Covered reports whether the kernel's preventive country sets drop packets
// from addr. Always false in observe mode or before the first load.
func (ce *countryEnforcer) Covered(addr netip.Addr) bool {
	if !ce.enforceActive {
		return false
	}
	return ce.set.Load().Contains(addr)
}

// kick nudges the loop without blocking; extra kicks while one is pending
// collapse into it.
func (ce *countryEnforcer) kick() {
	select {
	case ce.trigger <- struct{}{}:
	default:
	}
}

// Stats returns the per-country prefix counts and whether they are loaded.
func (ce *countryEnforcer) Stats() (map[string]int, bool) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	out := make(map[string]int, len(ce.counts))
	for k, v := range ce.counts {
		out[k] = v
	}
	return out, ce.loaded
}

// run refreshes immediately, then again on every list change; while the
// database is not available yet it retries every minute, and once loaded it
// re-walks daily to pick up the monthly database refresh.
func (ce *countryEnforcer) run(ctx context.Context) {
	for {
		ok := ce.refresh(ctx)
		wait := time.Minute
		if ok {
			wait = 24 * time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-ce.trigger:
		case <-time.After(wait):
		}
	}
}

func (ce *countryEnforcer) refresh(ctx context.Context) bool {
	codes := ce.list.Countries()
	if len(codes) == 0 {
		if err := ce.fw.SetCountryPrefixes(ctx, nil); err != nil {
			ce.warnf("firewall: clearing country prefixes: %v", err)
			return false
		}
		ce.store(nil, map[string]int{}, true)
		return true
	}

	enum, ok := ce.provider.(geoip.PrefixEnumerator)
	if !ok || !ce.provider.Available() {
		ce.store(nil, nil, false)
		return false
	}
	prefixes, counts, err := enum.CountryPrefixes(ctx, codes)
	if err != nil {
		if ctx.Err() == nil {
			ce.warnf("geoip: enumerating country prefixes: %v", err)
		}
		return false
	}
	if err := ce.fw.SetCountryPrefixes(ctx, prefixes); err != nil {
		ce.warnf("firewall: loading country prefixes: %v", err)
		return false
	}
	ce.store(prefixes, counts, true)
	ce.logf("firewall: country blocking covers %d prefixes (%s)", len(prefixes), summarizeCounts(counts))
	return true
}

// store records what the kernel now holds: the coverage matcher, the
// per-country counts and the loaded flag.
func (ce *countryEnforcer) store(prefixes []netip.Prefix, counts map[string]int, loaded bool) {
	if loaded {
		s := netset.New()
		for _, p := range prefixes {
			s.Add(p)
		}
		s.Build()
		ce.set.Store(s)
	}
	ce.mu.Lock()
	if counts != nil {
		ce.counts = counts
	}
	ce.loaded = loaded
	ce.mu.Unlock()
}

func summarizeCounts(counts map[string]int) string {
	parts := make([]string, 0, len(counts))
	for c, n := range counts {
		parts = append(parts, fmt.Sprintf("%s %d", c, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
