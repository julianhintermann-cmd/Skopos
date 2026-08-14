package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
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
	var sh shed
	if makeRoom(sources, base.Add(window/2), window, &sh) {
		t.Error("made room by forgetting sources that are still active")
	}
	if len(sources) != maxTrackedSources {
		t.Errorf("active sources were evicted: %d left", len(sources))
	}
	// Refusing to track a source is the serious half of the bound, so it is
	// counted rather than left for someone to deduce.
	if got := sh.stats(); got.Untracked != 1 || got.Forgotten != 0 {
		t.Errorf("a refused source went uncounted: %+v", got)
	}

	// Long silent: the space comes back, so a genuinely new source is tracked.
	if !makeRoom(sources, base.Add(idleFactor*window+time.Second), window, &sh) {
		t.Fatal("silent sources were not reclaimed")
	}
	if len(sources) != 0 {
		t.Errorf("expected the quiet entries to be gone, %d left", len(sources))
	}
	if got := sh.stats(); got.Forgotten != maxTrackedSources {
		t.Errorf("reclaimed entries went uncounted: %+v", got)
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

	var sh shed
	if !makeRoom(sources, now, window, &sh) {
		t.Fatal("the quiet sources should have been reclaimed")
	}
	if _, ok := sources[active]; !ok {
		t.Error("the source still sending was evicted")
	}
	if len(sources) != 1 {
		t.Errorf("only the active source should remain, got %d", len(sources))
	}
}

// The exact scenario the audit measured: fill the source map to its cap, wait
// a day, then have a genuinely new source flood. It used to raise nothing at
// all — permanently, for the life of the process — because the map was full of
// addresses last heard from weeks earlier and there was no way out.
func TestFloodIsStillDetectedAfterTheSourceMapFills(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	now := base
	c := &collector{}
	d := NewRate(RateConfig{
		Window: time.Minute, MaxNewConnections: 100,
		Severity: model.SeverityWarning,
	}, c, func() time.Time { return now })

	// One packet each from enough distinct sources to reach the cap.
	for i := range maxTrackedSources {
		src := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		d.Observe(syn(now, src, "192.168.1.10", 443))
	}
	if c.count() != 0 {
		t.Fatalf("setup should not have raised anything, got %d", c.count())
	}

	// A day later all of that is ancient history — and someone starts.
	now = base.Add(24 * time.Hour)
	for range 150 {
		d.Observe(syn(now, "203.0.113.9", "192.168.1.10", 443))
	}
	if c.count() == 0 {
		t.Fatal("a flood from a new source was ignored because the map was full of stale entries")
	}
}

// A backup or an rsync opens hundreds of connections in seconds. That is
// ordinary on a LAN and alarming from the internet, and one threshold for both
// meant the number that catches a flood cut off the machine doing the backup —
// mid-transfer, with the internal action set to reject.
func TestLANSourcesAreHeldToAHigherBarAndNeverAutoBlocked(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	lan := netip.MustParsePrefix("192.168.0.0/16")
	c := &collector{}
	d := NewRate(RateConfig{
		Window: time.Minute, MaxNewConnections: 100,
		Severity: model.SeverityWarning, Block: true,
		IsInternal: lan.Contains,
	}, c, func() time.Time { return now })

	// 200 connections from the operator's own network: over the external
	// limit, nowhere near the internal one.
	for range 200 {
		d.Observe(syn(now, "192.168.1.50", "9.9.9.9", 443))
	}
	if c.count() != 0 {
		t.Errorf("an ordinary LAN transfer raised %d findings", c.count())
	}

	// Far past even the raised bar: it fires, but must not propose a block.
	for range 1200 {
		d.Observe(syn(now, "192.168.1.50", "9.9.9.9", 443))
	}
	c.mu.Lock()
	lanFindings := append([]Finding(nil), c.findings...)
	c.findings = nil
	c.mu.Unlock()
	if len(lanFindings) == 0 {
		t.Fatal("a genuine LAN flood should still be reported")
	}
	if lanFindings[0].SuggestBlock {
		t.Error("a device on your own network must not be auto-blocked for talking too much")
	}

	// An external source at the same rate is still proposed for a block.
	for range 150 {
		d.Observe(syn(now, "203.0.113.9", "9.9.9.9", 443))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.findings) == 0 || !c.findings[0].SuggestBlock {
		t.Errorf("an external flood should still suggest a block, got %+v", c.findings)
	}
}
