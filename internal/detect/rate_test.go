package detect

import (
	"net/netip"
	"testing"
	"time"
)

// The window slides: events older than the window stop counting, so a source
// that stays just under the limit forever never fires.
func TestRateWindowSlides(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	const window = 10 * time.Second

	// 100 events spread over the first second.
	for i := 0; i < 100; i++ {
		w.add(base.Add(time.Duration(i)*10*time.Millisecond), window, 1)
	}
	if got := w.add(base.Add(time.Second), window, 0); got != 100 {
		t.Errorf("total inside the window = %d, want 100", got)
	}
	// Eleven seconds later everything has aged out.
	if got := w.add(base.Add(11*time.Second), window, 0); got != 0 {
		t.Errorf("total after the window passed = %d, want 0", got)
	}
	// A long idle gap resets rather than looping the ring.
	w.add(base.Add(time.Hour), window, 5)
	if got := w.add(base.Add(time.Hour), window, 0); got != 5 {
		t.Errorf("total after an idle hour = %d, want 5", got)
	}
}

// Counting is constant-memory: the old implementation kept one timestamp per
// packet, which at the shipped defaults meant eighty thousand per source.
func TestRateWindowIsConstantSize(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	const window = 10 * time.Second
	for i := 0; i < 200000; i++ {
		w.add(base.Add(time.Duration(i)*time.Microsecond), window, 1)
	}
	if len(w.counts) != rateBuckets {
		t.Errorf("bucket count = %d, want the fixed %d", len(w.counts), rateBuckets)
	}
	if w.total <= 0 || w.total > 200000 {
		t.Errorf("total = %d, want a plausible in-window count", w.total)
	}
}

func BenchmarkRateWindowAdd(b *testing.B) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	var w rateWindow
	for i := 0; i < b.N; i++ {
		w.add(base.Add(time.Duration(i)*time.Microsecond), 10*time.Second, 1)
	}
}

// The per-source maps used to grow to the cap and then refuse every new source
// forever. On a port-forwarded box the cap is reached in days to weeks, after
// which the map is full of addresses last heard from weeks earlier and the
// address attacking right now is the one that gets ignored — with nothing
// anywhere saying the detector has gone deaf.
func TestSourceMapReclaimsQuietSources(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	window := time.Minute
	sources := map[netip.Addr]*rateState{}
	for i := range maxTrackedSources {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		sources[addr] = &rateState{last: base}
	}
	if len(sources) != maxTrackedSources {
		t.Fatalf("setup: %d entries", len(sources))
	}

	// Still inside the window: nothing may be evicted, because those sources
	// are under active evaluation and dropping them is what a spoofed flood
	// would want.
	if makeRoom(sources, base.Add(window/2), window) {
		t.Error("made room by forgetting sources that are still active")
	}
	if len(sources) != maxTrackedSources {
		t.Errorf("active sources were evicted: %d left", len(sources))
	}

	// Long silent: the space comes back, so a genuinely new source is tracked.
	if !makeRoom(sources, base.Add(idleFactor*window+time.Second), window) {
		t.Fatal("silent sources were not reclaimed")
	}
	if len(sources) != 0 {
		t.Errorf("expected the quiet entries to be gone, %d left", len(sources))
	}
}

// A source heard from recently survives a sweep that clears its neighbours.
func TestSourceMapKeepsTheActiveOne(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	window := time.Minute
	active := netip.MustParseAddr("203.0.113.9")
	sources := map[netip.Addr]*rateState{}
	for i := range maxTrackedSources - 1 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		sources[addr] = &rateState{last: base}
	}
	now := base.Add(idleFactor*window + time.Second)
	sources[active] = &rateState{last: now}

	if !makeRoom(sources, now, window) {
		t.Fatal("the quiet sources should have been reclaimed")
	}
	if _, ok := sources[active]; !ok {
		t.Error("the source still sending was evicted")
	}
	if len(sources) != 1 {
		t.Errorf("only the active source should remain, got %d", len(sources))
	}
}
