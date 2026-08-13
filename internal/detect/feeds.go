package detect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/netset"
)

// builtinFeeds maps friendly names to their source URLs.
var builtinFeeds = map[string]string{
	"firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	"spamhaus_drop":  "https://www.spamhaus.org/drop/drop.txt",
}

// FeedResult is what a Fetcher returns for one feed.
type FeedResult struct {
	// Body is the feed content (one CIDR or IP per line, # comments allowed).
	Body []byte
	// ETag is the server's entity tag, echoed back on the next fetch so
	// unchanged feeds are not re-downloaded.
	ETag string
	// NotModified is true when the server answered 304 and Body is empty.
	NotModified bool
}

// Fetcher retrieves a feed. Implementations handle HTTP, ETag and timeouts;
// tests substitute a fake so feed logic is exercised without the network.
type Fetcher interface {
	Fetch(ctx context.Context, url, etag string) (FeedResult, error)
}

// FeedsConfig configures the blocklist detector.
type FeedsConfig struct {
	Lists    []string // built-in names or https:// URLs
	Refresh  time.Duration
	Severity model.Severity
	Block    bool
	// IsInternal excludes internal endpoints from matching (feeds are about
	// external threats).
	IsInternal func(netip.Addr) bool
}

// Feeds matches the external endpoint of each packet against downloaded IP
// blocklists. The active set is swapped atomically on refresh, so lookups
// never block on a download.
type Feeds struct {
	cfg     FeedsConfig
	sink    Sink
	fetcher Fetcher
	clock   Clock

	set atomic.Pointer[netset.Set]

	// cacheMu guards the per-URL ETag and last-good body cache, so a feed
	// answering 304 keeps contributing its entries to the rebuilt set.
	cacheMu sync.Mutex
	etags   map[string]string
	bodies  map[string][]byte

	firedMu sync.Mutex
	fired   map[netip.Addr]time.Time
}

// NewFeeds creates a feeds detector. The set starts empty until Refresh runs.
func NewFeeds(cfg FeedsConfig, sink Sink, fetcher Fetcher, clock Clock) *Feeds {
	if clock == nil {
		clock = time.Now
	}
	if cfg.IsInternal == nil {
		cfg.IsInternal = func(netip.Addr) bool { return false }
	}
	f := &Feeds{
		cfg:     cfg,
		sink:    sink,
		fetcher: fetcher,
		clock:   clock,
		etags:   make(map[string]string),
		bodies:  make(map[string][]byte),
		fired:   make(map[netip.Addr]time.Time),
	}
	empty := netset.New()
	empty.Build()
	f.set.Store(empty)
	return f
}

// resolveURL maps a configured list entry to its URL.
func resolveURL(entry string) (string, bool) {
	if u, ok := builtinFeeds[entry]; ok {
		return u, true
	}
	if strings.HasPrefix(entry, "https://") || strings.HasPrefix(entry, "http://") {
		return entry, true
	}
	return "", false
}

// Refresh downloads every configured feed and atomically swaps in a set
// rebuilt from the freshest body of each feed. A feed answering 304 reuses its
// cached body; a feed that fails to download keeps its previous body, so
// transient failures never shrink coverage. The error names any failures so
// the caller can send a system alert.
func (f *Feeds) Refresh(ctx context.Context) (loaded int, err error) {
	var failures []string

	for _, entry := range f.cfg.Lists {
		url, ok := resolveURL(entry)
		if !ok {
			failures = append(failures, fmt.Sprintf("%s (unknown feed)", entry))
			continue
		}
		f.cacheMu.Lock()
		prevETag := f.etags[url]
		f.cacheMu.Unlock()

		res, ferr := f.fetcher.Fetch(ctx, url, prevETag)
		if ferr != nil {
			failures = append(failures, fmt.Sprintf("%s (%v)", entry, ferr))
			continue
		}
		if res.NotModified {
			continue // cached body stays valid
		}
		f.cacheMu.Lock()
		f.bodies[url] = res.Body
		if res.ETag != "" {
			f.etags[url] = res.ETag
		}
		f.cacheMu.Unlock()
	}

	// Rebuild the active set from every cached feed body, so unchanged and
	// changed feeds all contribute.
	merged := netset.New()
	f.cacheMu.Lock()
	for _, body := range f.bodies {
		loaded += parseFeed(body, merged)
	}
	f.cacheMu.Unlock()
	merged.Build()
	f.set.Store(merged)

	if len(failures) > 0 {
		return loaded, fmt.Errorf("some feeds failed: %s", strings.Join(failures, "; "))
	}
	return loaded, nil
}

// parseFeed adds every valid CIDR/IP line to the set and returns the count.
func parseFeed(body []byte, set *netset.Set) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Spamhaus lines look like "1.2.3.0/24 ; SBL123"; keep the CIDR.
		if i := strings.IndexAny(line, " \t;"); i >= 0 {
			line = line[:i]
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			set.Add(p)
			n++
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			set.Add(netip.PrefixFrom(a, a.BitLen()))
			n++
		}
	}
	return n
}

var (
	cgnatRange  = netip.MustParsePrefix("100.64.0.0/10")
	v4Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// routableUnicast reports whether addr can plausibly be an external internet
// peer. Border-firewall lists like FireHOL Level 1 deliberately include bogon
// space — multicast, broadcast, CGNAT, RFC1918 — because at an internet edge
// such sources are spoofed. Inside a LAN those ranges are everyday traffic
// (mDNS, SSDP, DHCP broadcasts, carrier-grade NAT), so a feed match on them
// is an artifact, never a threat.
func routableUnicast(addr netip.Addr) bool {
	a := addr.Unmap()
	if !a.IsValid() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsLoopback() || a.IsUnspecified() || a.IsPrivate() {
		return false
	}
	if a.Is4() && (a == v4Broadcast || cgnatRange.Contains(a)) {
		return false
	}
	return true
}

// Observe implements flow.Observer. It checks the external endpoint of the
// packet against the blocklist set.
func (f *Feeds) Observe(p flow.Packet) {
	set := f.set.Load()
	if set == nil {
		return
	}
	// Determine which endpoint is the external peer.
	var peer netip.Addr
	switch {
	case !f.cfg.IsInternal(p.SrcIP):
		peer = p.SrcIP
	case !f.cfg.IsInternal(p.DstIP):
		peer = p.DstIP
	default:
		return // purely internal traffic
	}
	// Only judge addresses that can actually exist on the public internet.
	if !routableUnicast(peer) {
		return
	}
	if !set.Contains(peer) {
		return
	}

	now := p.Time
	if now.IsZero() {
		now = f.clock()
	}
	// De-dupe rapid repeats for the same peer; policy applies the real
	// cooldown, this just avoids flooding it.
	f.firedMu.Lock()
	if last, ok := f.fired[peer]; ok && now.Sub(last) < time.Minute {
		f.firedMu.Unlock()
		return
	}
	f.fired[peer] = now
	f.firedMu.Unlock()

	f.sink.Raise(Finding{
		Detector: "feeds", Source: peer, Severity: f.cfg.Severity, Port: p.DstPort,
		Title:        fmt.Sprintf("Blocklisted address %s", peer),
		Detail:       "matched a configured IP blocklist feed",
		SuggestBlock: f.cfg.Block,
	})
}

// Count returns the number of prefixes currently loaded.
func (f *Feeds) Count() int { return f.set.Load().Len() }

// Listed reports whether an address is in the currently loaded blocklists.
// The reputation card asks: an address the operator's own lists already
// condemn should not be presented as one nobody has anything on.
func (f *Feeds) Listed(addr netip.Addr) bool {
	if f == nil || !routableUnicast(addr) {
		return false
	}
	return f.set.Load().Contains(addr.Unmap())
}
