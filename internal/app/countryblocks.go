package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/geoip"
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

	trigger chan struct{}

	mu     sync.Mutex
	counts map[string]int
	loaded bool
}

func newCountryEnforcer(provider geoip.Provider, list *geoip.Blocklist, fw *firewall.Service, logf, warnf func(string, ...any)) *countryEnforcer {
	ce := &countryEnforcer{
		provider: provider,
		list:     list,
		fw:       fw,
		logf:     logf,
		warnf:    warnf,
		trigger:  make(chan struct{}, 1),
		counts:   map[string]int{},
	}
	list.SetOnChange(ce.kick)
	return ce
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
		ce.set(map[string]int{}, true)
		return true
	}

	enum, ok := ce.provider.(geoip.PrefixEnumerator)
	if !ok || !ce.provider.Available() {
		ce.set(nil, false)
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
	ce.set(counts, true)
	ce.logf("firewall: country blocking covers %d prefixes (%s)", len(prefixes), summarizeCounts(counts))
	return true
}

func (ce *countryEnforcer) set(counts map[string]int, loaded bool) {
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
