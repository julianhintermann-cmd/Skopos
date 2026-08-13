package blockwatch

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func pkt(src, dst string, at time.Time) flow.Packet {
	return flow.Packet{
		Time:  at,
		SrcIP: netip.MustParseAddr(src),
		DstIP: netip.MustParseAddr(dst),
	}
}

func block(prefix string) model.Block {
	return model.Block{Prefix: netip.MustParsePrefix(prefix), Active: true}
}

func TestWatchCountsHostAndCIDRHits(t *testing.T) {
	w := New()
	w.Update([]model.Block{block("203.0.113.5/32"), block("198.51.100.0/24")})

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	// Two packets from the blocked host, one into the blocked range, one
	// unrelated.
	w.Observe(pkt("203.0.113.5", "192.168.1.10", now))
	w.Observe(pkt("203.0.113.5", "192.168.1.10", now.Add(time.Second)))
	w.Observe(pkt("192.168.1.10", "198.51.100.77", now.Add(2*time.Second)))
	w.Observe(pkt("8.8.8.8", "192.168.1.10", now))

	stats := w.Stats()
	if got := stats["203.0.113.5/32"].Attempts; got != 2 {
		t.Errorf("host attempts = %d, want 2", got)
	}
	if got := stats["203.0.113.5/32"].Last; !got.Equal(now.Add(time.Second)) {
		t.Errorf("host last = %v, want %v", got, now.Add(time.Second))
	}
	if got := stats["198.51.100.0/24"].Attempts; got != 1 {
		t.Errorf("cidr attempts = %d, want 1", got)
	}
	if len(stats) != 2 {
		t.Errorf("stats entries = %d, want 2", len(stats))
	}
}

func TestWatchContains(t *testing.T) {
	w := New()
	if w.Contains(netip.MustParseAddr("203.0.113.5")) {
		t.Error("empty watch must match nothing")
	}
	w.Update([]model.Block{block("203.0.113.5/32"), block("198.51.100.0/24")})
	for addr, want := range map[string]bool{
		"203.0.113.5":   true,
		"198.51.100.99": true,
		"203.0.113.6":   false,
		"192.168.1.1":   false,
	} {
		if got := w.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestWatchUpdateDropsRemovedTallies(t *testing.T) {
	w := New()
	w.Update([]model.Block{block("203.0.113.5/32"), block("198.51.100.0/24")})
	now := time.Now()
	w.Observe(pkt("203.0.113.5", "192.168.1.10", now))
	w.Observe(pkt("198.51.100.7", "192.168.1.10", now))

	// The host block is unblocked; its tally must go, the other must stay.
	w.Update([]model.Block{block("198.51.100.0/24")})
	stats := w.Stats()
	if _, ok := stats["203.0.113.5/32"]; ok {
		t.Error("tally of a removed block must be dropped")
	}
	if got := stats["198.51.100.0/24"].Attempts; got != 1 {
		t.Errorf("surviving tally = %d, want 1", got)
	}
	if w.Contains(netip.MustParseAddr("203.0.113.5")) {
		t.Error("removed block must no longer match")
	}
}

func TestWatchCountsBothEndpointsOnce(t *testing.T) {
	w := New()
	w.Update([]model.Block{block("203.0.113.5/32")})
	// The blocked address as destination counts too (outbound attempt seen
	// before the output hook drops it, or a LAN peer trying to reach it).
	w.Observe(pkt("192.168.1.10", "203.0.113.5", time.Now()))
	if got := w.Stats()["203.0.113.5/32"].Attempts; got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}
