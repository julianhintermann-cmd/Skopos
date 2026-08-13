package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// CountryBlockConfig configures the blocked-country detector.
type CountryBlockConfig struct {
	// Lookup resolves an address to an ISO country code.
	Lookup func(netip.Addr) (string, bool)
	// Blocked reports whether a country is on the operator's block list;
	// Empty lets the detector skip lookups entirely while the list is empty.
	Blocked func(string) bool
	Empty   func() bool
	// IsInternal classifies addresses (the detector only judges inbound
	// traffic from external sources).
	IsInternal func(netip.Addr) bool
	// Covered reports whether the kernel's preventive country sets already
	// drop this source. The reactive path then stays silent: the packet is
	// dead either way, and raising would only pile alerts and redundant
	// per-IP blocks onto traffic that is already handled. Optional.
	Covered func(netip.Addr) bool
}

// CountryBlock raises a blocking finding for inbound traffic from blocked
// countries. It is reactive by design: rather than loading hundreds of
// thousands of prefixes into the kernel, it blocks sources from those
// countries the moment they actually appear — with the policy layer's
// cooldown, TTL and allowlist protections applying as usual.
type CountryBlock struct {
	cfg  CountryBlockConfig
	sink Sink
	now  Clock

	mu   sync.Mutex
	seen map[netip.Addr]time.Time // per-source raise throttle
}

// NewCountryBlock creates the detector.
func NewCountryBlock(cfg CountryBlockConfig, sink Sink, now Clock) *CountryBlock {
	if now == nil {
		now = time.Now
	}
	return &CountryBlock{cfg: cfg, sink: sink, now: now, seen: map[netip.Addr]time.Time{}}
}

// throttle is how often the detector re-raises for the same source. The
// policy cooldown dedupes notifications anyway; this just keeps the packet
// path from hammering the sink during a flood.
const countryThrottle = 30 * time.Second

// Observe implements flow.Observer.
func (c *CountryBlock) Observe(p flow.Packet) {
	if c.cfg.Empty() {
		return
	}
	// Inbound only: external source, internal destination.
	if c.cfg.IsInternal(p.SrcIP) || !c.cfg.IsInternal(p.DstIP) {
		return
	}
	// Connection attempts only (TCP SYN). Reply packets of connections the
	// LAN opened itself arrive here precisely because the kernel's conntrack
	// exemption lets them through — blocking their sender would kill exactly
	// the traffic that exemption protects (it once broke Skopos' own RDAP
	// lookups against a registry in a blocked country). Unsolicited UDP is
	// left to the preventive kernel sets.
	if !p.SYN {
		return
	}
	code, ok := c.cfg.Lookup(p.SrcIP)
	if !ok || !c.cfg.Blocked(code) {
		return
	}
	// Already dropped in-kernel by the preventive sets — nothing to add.
	if c.cfg.Covered != nil && c.cfg.Covered(p.SrcIP) {
		return
	}

	now := c.now()
	c.mu.Lock()
	if last, ok := c.seen[p.SrcIP]; ok && now.Sub(last) < countryThrottle {
		c.mu.Unlock()
		return
	}
	c.seen[p.SrcIP] = now
	// Bound the throttle map; a scan from many addresses must not grow it
	// without limit.
	if len(c.seen) > 4096 {
		for k, t := range c.seen {
			if now.Sub(t) > countryThrottle {
				delete(c.seen, k)
			}
		}
	}
	c.mu.Unlock()

	c.sink.Raise(Finding{
		Detector: "country",
		Source:   p.SrcIP,
		Severity: model.SeverityWarning,
		Title:    fmt.Sprintf("Traffic from blocked country %s", code),
		Detail:   fmt.Sprintf("%s connected to %s:%d (country %s is on the block list).", p.SrcIP, p.DstIP, p.DstPort, code),
		Port:     p.DstPort,
		// The whole point of the list: block the source on sight.
		SuggestBlock: true,
	})
}
