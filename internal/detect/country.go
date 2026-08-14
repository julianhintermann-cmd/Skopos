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

	shed shed
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
	c.reclaim(now)
	c.seen[p.SrcIP] = now
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

// reclaim bounds the throttle map. Callers hold c.mu.
//
// The old sweep had no cap behind it: past 4096 entries it walked the whole
// map on every SYN and deleted only entries older than the throttle, so a
// spoofed flood or a botnet sweep from more than 4096 addresses inside 30
// seconds deleted nothing and walked it all again on the next packet — O(n)
// per frame, on the capture goroutine, growing without limit. The detector
// meant to watch a flood was what made Skopos stop reading frames during one.
//
// The same ageing pass runs here, but only when the map is genuinely full, and
// if it cannot free half the map the memo is dropped whole (as Feeds does).
// Either way the next pass is at least maxTrackedSources/2 insertions away, so
// the per-packet cost is constant. Dropping the memo costs at most one extra
// raise per source still in flight, which the policy cooldown absorbs — and it
// is counted, so an overrun shows up as a number instead of as a mystery.
func (c *CountryBlock) reclaim(now time.Time) {
	if len(c.seen) < maxTrackedSources {
		return
	}
	before := len(c.seen)
	for addr, t := range c.seen {
		if now.Sub(t) >= countryThrottle {
			delete(c.seen, addr)
		}
	}
	if len(c.seen) > maxTrackedSources/2 {
		c.seen = make(map[netip.Addr]time.Time, maxTrackedSources)
	}
	c.shed.forgotten.Add(uint64(before - len(c.seen)))
}

// Shed reports the throttle entries this detector has had to forget. Sources
// forgotten while still inside the throttle window can raise one extra finding
// each, so a non-zero and climbing value is the signal that the reactive
// country path is being overrun.
func (c *CountryBlock) Shed() ShedStats { return c.shed.stats() }
