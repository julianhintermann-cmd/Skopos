package detect

import (
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// distinctPortsOn and distinctTargetsOn are how the port-scan thresholds were
// evaluated before they were kept incrementally: a fresh map and a full walk of
// the attempt ring, per SYN. They are the oracle the counters are checked
// against, because the point of that change was to be faster at exactly the
// same numbers — a detector that fires at a different moment than it used to
// is a behaviour change wearing a performance change's clothes.
func distinctPortsOn(attempts []attempt, target netip.Addr) int {
	seen := make(map[uint16]struct{})
	for _, a := range attempts {
		if a.target == target {
			seen[a.port] = struct{}{}
		}
	}
	return len(seen)
}

func distinctTargetsOn(attempts []attempt, port uint16) int {
	seen := make(map[netip.Addr]struct{})
	for _, a := range attempts {
		if a.port == port {
			seen[a.target] = struct{}{}
		}
	}
	return len(seen)
}

// The incremental counts must equal the full walk after every packet, through
// repeats, through the window sliding, and through the attempt ring overflowing
// its cap — those are the three ways an entry leaves, and a count that misses
// one drifts away from the threshold it feeds.
func TestPortscanDistinctCountsMatchAFullWalk(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("203.0.113.7")
	d := NewPortscan(PortscanConfig{
		Window: time.Minute,
		// Out of reach: this test is about the counts, not the findings.
		External:   Thresholds{Ports: 1 << 20, Targets: 1 << 20},
		Internal:   Thresholds{Ports: 1 << 20, Targets: 1 << 20},
		Severity:   model.SeverityWarning,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return base })
	// A small ring so the cap is reached inside a window and its eviction path
	// is exercised too.
	d.maxAttempts = 64

	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 4000 {
		target := netip.AddrFrom4([4]byte{192, 168, 1, byte(rng.IntN(4))})
		port := uint16(1 + rng.IntN(6))
		// A tenth of a window per step, so the window slides over the run and
		// bursts of same-instant packets still overflow the ring.
		at := base.Add(time.Duration(i) * 6 * time.Second / 10)
		d.Observe(flow.Packet{
			Time: at, SrcIP: src, DstIP: target, SrcPort: 40000, DstPort: port,
			Proto: model.ProtoTCP, SYN: true, Size: 60,
		})

		st := d.sources[src]
		if len(st.attempts) > d.maxAttempts {
			t.Fatalf("step %d: ring holds %d attempts, cap is %d", i, len(st.attempts), d.maxAttempts)
		}
		if got, want := st.portsOn[target], distinctPortsOn(st.attempts, target); got != want {
			t.Fatalf("step %d: distinct ports on %s = %d, full walk says %d", i, target, got, want)
		}
		if got, want := st.targetsOn[port], distinctTargetsOn(st.attempts, port); got != want {
			t.Fatalf("step %d: distinct targets on port %d = %d, full walk says %d", i, port, got, want)
		}
	}

	// Nothing may outlive the attempts that put it there: a stale index entry
	// is a slow leak per source, which is what the ring cap exists to prevent.
	st := d.sources[src]
	if len(st.live) > len(st.attempts) {
		t.Errorf("index holds %d pairs for %d attempts", len(st.live), len(st.attempts))
	}
	for target, n := range st.portsOn {
		if n <= 0 {
			t.Errorf("target %s left behind a zero count", target)
		}
	}
	for port, n := range st.targetsOn {
		if n <= 0 {
			t.Errorf("port %d left behind a zero count", port)
		}
	}
}

// Once the window has emptied, so has everything derived from it.
func TestPortscanIndexEmptiesWithTheWindow(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	src := netip.MustParseAddr("203.0.113.7")
	d := NewPortscan(PortscanConfig{
		Window: time.Minute, External: Thresholds{Ports: 15, Targets: 20},
		Severity: model.SeverityWarning, IsInternal: func(netip.Addr) bool { return false },
	}, &nopSink{}, func() time.Time { return base })

	for port := range uint16(10) {
		d.Observe(syn(base, "203.0.113.7", "192.168.1.10", port+1))
	}
	// One packet a full window later: everything before it has expired.
	d.Observe(syn(base.Add(2*time.Minute), "203.0.113.7", "192.168.1.10", 443))

	st := d.sources[src]
	if len(st.attempts) != 1 || len(st.live) != 1 || len(st.portsOn) != 1 || len(st.targetsOn) != 1 {
		t.Fatalf("stale state survived the window: %d attempts, %d pairs, %d targets, %d ports",
			len(st.attempts), len(st.live), len(st.portsOn), len(st.targetsOn))
	}
	if got := st.portsOn[netip.MustParseAddr("192.168.1.10")]; got != 1 {
		t.Errorf("distinct ports on the target = %d, want 1", got)
	}
}

// The throttle map used to have no cap at all — only a sweep, which deleted
// nothing while every entry was fresh and ran again on the very next SYN.
func TestCountryThrottleMapStaysBoundedUnderAFlood(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	sink := &nopSink{}
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     func(netip.Addr) (string, bool) { return "RU", true },
		Blocked:    func(string) bool { return true },
		Empty:      func() bool { return false },
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, sink, func() time.Time { return now })

	lan := netip.MustParseAddr("192.168.1.10")
	// Every source distinct and every one of them fresh: the shape a spoofed
	// SYN flood has, and the shape the old sweep could not do anything about.
	const sources = 3 * maxTrackedSources
	for i := range sources {
		det.Observe(flow.Packet{
			SrcIP: benchAddr(i), DstIP: lan, SrcPort: 40000, DstPort: 22,
			Proto: model.ProtoTCP, SYN: true, Size: 60,
		})
	}

	det.mu.Lock()
	held := len(det.seen)
	det.mu.Unlock()
	if held > maxTrackedSources {
		t.Errorf("throttle map holds %d entries, cap is %d", held, maxTrackedSources)
	}
	// Every source is new, so every one of them is a real finding: bounding
	// the throttle must not cost detection.
	if sink.n != sources {
		t.Errorf("raised %d findings for %d distinct blocked sources", sink.n, sources)
	}
	// And what the bound cost has a number on it.
	if got := det.Shed(); got.Forgotten == 0 {
		t.Error("the throttle shed entries without counting them")
	}
}

// Below the bound the throttle is untouched: one raise per source per window,
// which is the property the detector's own test pins from the outside.
func TestCountryThrottleUnchangedBelowTheBound(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	sink := &nopSink{}
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     func(netip.Addr) (string, bool) { return "RU", true },
		Blocked:    func(string) bool { return true },
		Empty:      func() bool { return false },
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, sink, func() time.Time { return now })

	lan := netip.MustParseAddr("192.168.1.10")
	pkt := flow.Packet{DstIP: lan, SrcPort: 40000, DstPort: 22, Proto: model.ProtoTCP, SYN: true, Size: 60}
	for range 50 {
		for i := range 100 {
			p := pkt
			p.SrcIP = benchAddr(i)
			det.Observe(p)
		}
	}
	if sink.n != 100 {
		t.Errorf("raised %d findings, want one per source", sink.n)
	}
	if got := det.Shed(); got.Forgotten != 0 {
		t.Errorf("shed %d entries while well inside the bound", got.Forgotten)
	}
}

// The baseline map used to refuse every new device past 1024 and never evict
// anything, so the first 1024 addresses ever seen held the slots for the life
// of the process. SLAAC privacy addresses rotate daily, so a home LAN gets
// there on its own in a few months — and then stops baselining anything, in
// silence.
func TestBaselineLearnsNewDevicesAfterTheMapFills(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	now := base
	det := NewBaseline(BaselineConfig{
		Bucket:     time.Hour,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return now })

	wan := netip.MustParseAddr("198.51.100.4")
	fill := func(addr netip.Addr, at time.Time) {
		det.Observe(flow.Packet{
			Time: at, SrcIP: addr, DstIP: wan, SrcPort: 40000, DstPort: 443,
			Proto: model.ProtoTCP, Size: 1500,
		})
	}
	// Yesterday's addresses, enough of them to fill the map.
	for i := range maxTrackedSources {
		fill(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), base)
	}
	if got := det.Devices(); got != maxTrackedSources {
		t.Fatalf("setup: %d devices tracked", got)
	}

	// A day later, a device with a freshly rotated address turns up.
	now = base.Add(24 * time.Hour)
	fresh := netip.MustParseAddr("10.9.9.9")
	fill(fresh, now)

	det.mu.Lock()
	_, tracked := det.devices[fresh]
	det.mu.Unlock()
	if !tracked {
		t.Fatal("a new device was refused a baseline because the map was full of stale ones")
	}
	if got := det.Shed(); got.Forgotten == 0 {
		t.Error("baselines were reclaimed without counting them")
	}
}

// Devices that are merely quiet this hour are not the ones to reclaim: their
// history is what the detector judges against.
func TestBaselineKeepsActiveDevicesWhenItReclaims(t *testing.T) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	now := base
	det := NewBaseline(BaselineConfig{
		Bucket:     time.Hour,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return now })

	wan := netip.MustParseAddr("198.51.100.4")
	send := func(addr netip.Addr) {
		det.Observe(flow.Packet{
			Time: now, SrcIP: addr, DstIP: wan, SrcPort: 40000, DstPort: 443,
			Proto: model.ProtoTCP, Size: 1500,
		})
	}
	active := netip.MustParseAddr("10.0.0.1")
	send(active)
	for i := 1; i < maxTrackedSources; i++ {
		send(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}

	// The active device keeps sending; the rest go quiet for a day.
	now = base.Add(24 * time.Hour)
	send(active)
	send(netip.MustParseAddr("10.200.200.200"))

	det.mu.Lock()
	_, kept := det.devices[active]
	det.mu.Unlock()
	if !kept {
		t.Error("the device that was still sending lost its baseline")
	}
}
