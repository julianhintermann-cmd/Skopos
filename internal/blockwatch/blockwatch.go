// Package blockwatch counts captured packets that touch active blocks. The
// capture tap sits before netfilter, so packets from a blocked peer still
// reach Skopos while the kernel drops them — which looks exactly like a
// broken firewall unless it is made visible. These tallies are that
// visibility: in enforce mode they are packets the kernel dropped; in observe
// mode they are packets a block would have dropped.
package blockwatch

import (
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Stat is one block's attempt tally.
type Stat struct {
	Attempts uint64
	Last     time.Time
}

type cidrEntry struct {
	prefix netip.Prefix
	key    string
}

// Watch matches packets against the active block list. Update rebuilds the
// matcher; Observe runs on the packet path and must stay cheap.
type Watch struct {
	mu    sync.RWMutex
	hosts map[netip.Addr]string // single-address blocks (the common case) — O(1)
	cidrs []cidrEntry           // real ranges, scanned linearly (rare, short)
	stats map[string]*Stat      // prefix string → tally, survives Update
}

// New returns an empty watch; nothing matches until Update runs.
func New() *Watch {
	return &Watch{hosts: map[netip.Addr]string{}, stats: map[string]*Stat{}}
}

// Update rebuilds the matcher from the active blocks, keeping the tallies of
// blocks that stayed and dropping those of removed ones.
func (w *Watch) Update(blocks []model.Block) {
	hosts := make(map[netip.Addr]string, len(blocks))
	var cidrs []cidrEntry
	keep := make(map[string]bool, len(blocks))
	for _, b := range blocks {
		if !b.Prefix.IsValid() {
			continue
		}
		key := b.Prefix.String()
		keep[key] = true
		if b.Prefix.IsSingleIP() {
			hosts[b.Prefix.Addr().Unmap()] = key
		} else {
			cidrs = append(cidrs, cidrEntry{prefix: b.Prefix, key: key})
		}
	}
	w.mu.Lock()
	w.hosts, w.cidrs = hosts, cidrs
	for k := range w.stats {
		if !keep[k] {
			delete(w.stats, k)
		}
	}
	w.mu.Unlock()
}

// Contains reports whether addr falls inside any active block.
func (w *Watch) Contains(addr netip.Addr) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lookup(addr) != ""
}

// lookup returns the matching block's prefix key, or "". Callers hold w.mu.
func (w *Watch) lookup(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	a := addr.Unmap()
	if k, ok := w.hosts[a]; ok {
		return k
	}
	for _, e := range w.cidrs {
		if e.prefix.Contains(a) {
			return e.key
		}
	}
	return ""
}

// Observe implements flow.Observer: every captured packet touching a blocked
// prefix bumps that block's tally.
func (w *Watch) Observe(p flow.Packet) {
	w.mu.RLock()
	srcKey := w.lookup(p.SrcIP)
	dstKey := w.lookup(p.DstIP)
	w.mu.RUnlock()
	if srcKey == "" && dstKey == "" {
		return
	}
	now := p.Time
	if now.IsZero() {
		now = time.Now()
	}
	w.mu.Lock()
	w.bump(srcKey, now)
	if dstKey != srcKey {
		w.bump(dstKey, now)
	}
	w.mu.Unlock()
}

// bump increments one tally. Callers hold w.mu for writing.
func (w *Watch) bump(key string, now time.Time) {
	if key == "" {
		return
	}
	st := w.stats[key]
	if st == nil {
		st = &Stat{}
		w.stats[key] = st
	}
	st.Attempts++
	if now.After(st.Last) {
		st.Last = now
	}
}

// Stats returns a copy of every tally keyed by prefix string.
func (w *Watch) Stats() map[string]Stat {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[string]Stat, len(w.stats))
	for k, v := range w.stats {
		out[k] = *v
	}
	return out
}
