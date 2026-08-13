// Package names turns the name observations the parser harvests — DNS and
// mDNS answers, TLS SNI — into a live address→name map and a durable passive
// DNS record. It is what makes the dashboard say "youtube.com" where it used
// to say 142.250.185.78.
package names

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// maxCached bounds the in-memory map. A home network resolves a few thousand
// distinct addresses a day; well past that the oldest entries are dropped
// wholesale rather than tracked individually, which keeps the packet path
// free of eviction bookkeeping.
const maxCached = 50000

// Store is the persistence the resolver needs.
type Store interface {
	UpsertNames(ctx context.Context, obs []store.NameObservation) error
	UpsertFingerprints(ctx context.Context, obs []store.FingerprintObservation) error
	KnownNames(ctx context.Context, limit int) (map[string]string, error)
}

// Resolver observes packets, learns names, and answers lookups. Lookup runs
// on the aggregation path, so it takes only a read lock; writes are buffered
// and flushed by a background loop.
type Resolver struct {
	store      Store
	isInternal func(netip.Addr) bool
	clock      func() time.Time
	log        func(string, ...any)

	mu    sync.RWMutex
	names map[netip.Addr]string

	pendMu sync.Mutex
	pend   map[nameKey]store.NameObservation
	pendFP map[fpKey]store.FingerprintObservation
}

type nameKey struct{ ip, name string }
type fpKey struct{ ip, ja4 string }

// New creates a resolver. isInternal decides whose fingerprints are worth
// recording (LAN devices, not the whole internet).
func New(st Store, isInternal func(netip.Addr) bool, clock func() time.Time) *Resolver {
	if clock == nil {
		clock = time.Now
	}
	if isInternal == nil {
		isInternal = func(netip.Addr) bool { return false }
	}
	return &Resolver{
		store:      st,
		isInternal: isInternal,
		clock:      clock,
		log:        func(string, ...any) {},
		names:      make(map[netip.Addr]string),
		pend:       make(map[nameKey]store.NameObservation),
		pendFP:     make(map[fpKey]store.FingerprintObservation),
	}
}

// SetLogger installs a logging callback.
func (r *Resolver) SetLogger(f func(string, ...any)) { r.log = f }

// Warm loads persisted names so a restart does not forget the network's
// vocabulary.
func (r *Resolver) Warm(ctx context.Context) error {
	known, err := r.store.KnownNames(ctx, maxCached)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, name := range known {
		if addr, err := netip.ParseAddr(ip); err == nil {
			r.names[addr] = name
		}
	}
	return nil
}

// Lookup returns the best known name for an address, or "".
func (r *Resolver) Lookup(addr netip.Addr) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names[addr.Unmap()]
}

// Observe implements flow.Observer: it harvests whatever the parser attached.
func (r *Resolver) Observe(p flow.Packet) {
	if len(p.Names) == 0 && p.JA4 == "" {
		return
	}
	now := p.Time
	if now.IsZero() {
		now = r.clock()
	}

	for _, rec := range p.Names {
		name := normalize(rec.Name)
		if name == "" || !rec.Addr.IsValid() {
			continue
		}
		source := "dns"
		switch {
		case strings.HasSuffix(name, ".local"):
			source = "mdns"
		case rec.TTL == 0 && p.Proto.String() == "tcp":
			source = "sni"
		}
		r.learn(rec.Addr, name, source, now)
	}

	// Fingerprints belong to the client that sent the hello, and only LAN
	// clients are ours to inventory.
	if p.JA4 != "" && r.isInternal(p.SrcIP) {
		r.pendMu.Lock()
		r.pendFP[fpKey{p.SrcIP.String(), p.JA4}] = store.FingerprintObservation{
			DeviceIP: p.SrcIP.String(), JA4: p.JA4, Time: now,
		}
		r.pendMu.Unlock()
	}
}

// learn records a mapping in the live map and queues it for persistence.
func (r *Resolver) learn(addr netip.Addr, name, source string, now time.Time) {
	addr = addr.Unmap()
	r.mu.Lock()
	if len(r.names) >= maxCached {
		// Bounded and simple: start over rather than carry eviction state on
		// the packet path. The durable table keeps the history, and Warm
		// repopulates the useful entries after a restart.
		r.names = make(map[netip.Addr]string, maxCached/4)
	}
	changed := r.names[addr] != name
	r.names[addr] = name
	r.mu.Unlock()
	if !changed {
		// Still worth counting a hit occasionally, but not on every packet:
		// the flush loop coalesces, so only new mappings are queued.
		return
	}

	r.pendMu.Lock()
	r.pend[nameKey{addr.String(), name}] = store.NameObservation{
		IP: addr.String(), Name: name, Source: source, Time: now,
	}
	r.pendMu.Unlock()
}

// Run flushes buffered observations on an interval until ctx is cancelled.
func (r *Resolver) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.flush(context.WithoutCancel(ctx))
			return
		case <-t.C:
			r.flush(ctx)
		}
	}
}

func (r *Resolver) flush(ctx context.Context) {
	r.pendMu.Lock()
	names := make([]store.NameObservation, 0, len(r.pend))
	for _, o := range r.pend {
		names = append(names, o)
	}
	fps := make([]store.FingerprintObservation, 0, len(r.pendFP))
	for _, o := range r.pendFP {
		fps = append(fps, o)
	}
	r.pend = make(map[nameKey]store.NameObservation)
	r.pendFP = make(map[fpKey]store.FingerprintObservation)
	r.pendMu.Unlock()

	if err := r.store.UpsertNames(ctx, names); err != nil {
		r.log("names: persisting %d names: %v", len(names), err)
	}
	if err := r.store.UpsertFingerprints(ctx, fps); err != nil {
		r.log("names: persisting %d fingerprints: %v", len(fps), err)
	}
}

// normalize lower-cases a name and strips the trailing dot, rejecting
// anything that is not plausibly a hostname.
func normalize(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 || !strings.Contains(name, ".") {
		return ""
	}
	for _, c := range name {
		if c > 0x7e || c < 0x21 {
			return ""
		}
	}
	return name
}
