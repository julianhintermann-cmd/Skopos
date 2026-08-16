package detect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sort"
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

// feedContains records which built-in feeds are aggregates of which others.
//
// FireHOL Level 1 is not a list in its own right; it is a merge, and among the
// things it merges are Spamhaus DROP and DShield's top-attackers set. Both of
// those are also things Skopos consults directly — DROP is the other default
// feed, DShield is a reputation source — so a match reported naively reads as
// two or three independent sources agreeing when it is one fact counted twice.
// Listed collapses a contained name into its container for exactly that reason.
var feedContains = map[string][]string{
	"firehol_level1": {"spamhaus_drop", "dshield"},
}

// feedDescriptions says what a built-in list actually is, so the reputation
// card can print it beside the name.
//
// This is the honest answer to a problem a filter cannot fix. FireHOL Level 1
// holds roughly 611 million addresses, and about 596 million of them —
// something like 97% — are Team Cymru's fullbogons: unallocated space, and
// space an RIR holds but has not assigned to anyone. That set changes as
// allocations are made, so no static range list in this file can identify it.
// What Skopos can do is stop letting "on firehol_level1" read as "confirmed
// attacker", because most of the time it means "from an address nobody should
// be routing".
//
// A name with no entry here is an operator's own URL, and Skopos has nothing
// to say about what it contains.
var feedDescriptions = map[string]string{
	"firehol_level1": "aggregate; mostly unallocated address space, not observed attackers",
	"spamhaus_drop":  "netblocks hijacked or leased by criminal operations",
}

// FeedDescription returns the note for a built-in list, empty for anything
// else.
func FeedDescription(name string) string { return feedDescriptions[name] }

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

// listSet is one blocklist's entries under the name the operator configured
// it as. Kept apart from the merged set so a match can be attributed: an
// address on Spamhaus DROP and an address on somebody's homemade list are
// evidence of very different weight, and collapsing both to "on a blocklist"
// throws away the only part an operator can act on.
type listSet struct {
	name string
	set  *netset.Set
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

	// lists holds the same entries split by the list they came from. Every
	// packet is tested against the merged set above; these are walked only when
	// someone opens an address and asks why it is flagged.
	lists atomic.Pointer[[]listSet]

	// cacheMu guards the per-URL ETag and last-good body cache, so a feed
	// answering 304 keeps contributing its entries to the rebuilt set.
	cacheMu sync.Mutex
	etags   map[string]string
	bodies  map[string][]byte
	names   map[string]string // url → the name the operator configured it under

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
		names:   make(map[string]string),
		fired:   make(map[netip.Addr]time.Time),
	}
	empty := netset.New()
	empty.Build()
	f.set.Store(empty)
	f.lists.Store(&[]listSet{})
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
		f.names[url] = entry
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
	// changed feeds all contribute. Each body is parsed a second time into a
	// set of its own; that costs a few thousand lines per refresh interval and
	// buys the ability to name the list an address is on, which is the
	// difference between a card an operator can act on and one that just says
	// "flagged".
	merged := netset.New()
	var lists []listSet
	f.cacheMu.Lock()
	for url, body := range f.bodies {
		loaded += parseFeed(body, merged)
		per := netset.New()
		parseFeed(body, per)
		per.Build()
		name := f.names[url]
		if name == "" {
			name = url
		}
		lists = append(lists, listSet{name: name, set: per})
	}
	f.cacheMu.Unlock()
	merged.Build()
	f.set.Store(merged)
	// Sorted so the card names lists in a stable order rather than in Go's
	// randomised map order, which would otherwise reshuffle on every refresh.
	sort.Slice(lists, func(i, j int) bool { return lists[i].name < lists[j].name })
	f.lists.Store(&lists)

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

	// reservedV4 is IANA special-purpose space not already covered by netip's
	// own predicates. None of it can be a real internet peer, so a feed match
	// on one of these addresses is an artifact rather than a threat.
	//
	// The three documentation ranges (192.0.2.0/24, 198.51.100.0/24,
	// 203.0.113.0/24) are deliberately absent. They belong here on the merits
	// — a border list includes them and they cannot route — but they are also
	// the conventional stand-in for "some external address" in tests, and
	// excluding them here would force every future test of this path to use an
	// address that really belongs to somebody. They are a rounding error
	// against the actual problem anyway; see the note on feedDescriptions.
	reservedV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
		netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
		netip.MustParsePrefix("240.0.0.0/4"),   // reserved, and 255.255.255.255
	}
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
	// The reserved ranges below are the reason this check exists at all.
	//
	// FireHOL Level 1 is an aggregate, and by address count it is
	// overwhelmingly Team Cymru's fullbogons — unallocated space and space an
	// RIR holds but has not assigned — rather than observed attackers. Roughly
	// 596 million of its ~611 million addresses are bogons. A packet from one
	// of those is spoofed or misrouted, which is worth nothing as a reputation
	// signal and everything as noise: it would have the card announce that an
	// address is "on a blocklist you subscribe to" for the least interesting
	// possible reason.
	//
	// The RFC1918/CGNAT/multicast cases above covered the ranges a LAN sees
	// every day; these cover the rest of the reserved space, which a border
	// list includes for the same reason and which reaches a NAS just as easily.
	for _, r := range reservedV4 {
		if r.Contains(a) {
			return false
		}
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
	if len(f.fired) >= maxTrackedSources {
		// Drop the whole memo rather than grow without bound: the worst case
		// is one repeated alert per source, which the policy cooldown then
		// absorbs anyway.
		f.fired = make(map[netip.Addr]time.Time, maxTrackedSources)
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

// Listed names every loaded blocklist that contains the address, empty when
// none does. The reputation card asks: an address the operator's own lists
// already condemn should not be presented as one nobody has anything on — and
// the answer has to say which list, because that is what decides whether the
// match means anything.
func (f *Feeds) Listed(addr netip.Addr) []string {
	if f == nil || !routableUnicast(addr) {
		return nil
	}
	a := addr.Unmap()
	lists := f.lists.Load()
	if lists == nil {
		return nil
	}
	var hits []string
	for _, l := range *lists {
		if l.set.Contains(a) {
			hits = append(hits, l.name)
		}
	}
	return collapseContained(hits)
}

// collapseContained drops any hit that a another hit already includes, so an
// aggregate and its own ingredient are reported once rather than as two
// sources that happen to agree.
func collapseContained(hits []string) []string {
	if len(hits) < 2 {
		return hits
	}
	covered := map[string]bool{}
	for _, h := range hits {
		for _, inner := range feedContains[h] {
			covered[inner] = true
		}
	}
	out := hits[:0:0]
	for _, h := range hits {
		if !covered[h] {
			out = append(out, h)
		}
	}
	return out
}
