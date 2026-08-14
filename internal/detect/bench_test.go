package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// The detectors run inline on the capture goroutine — Aggregator.Add calls the
// observer fan-out for every packet it keeps — so their per-packet cost is the
// rate at which Skopos can read frames before the kernel starts dropping them.
// Correctness tests cannot see that; these can. Each benchmark reproduces the
// steady state of a flood rather than a cold detector, because the cost bugs
// both live past the point where the per-source state has filled up.

// nopSink is the cheapest possible Sink: these measure detector cost, not what
// the policy layer does with a finding.
type nopSink struct{ n int }

func (s *nopSink) Raise(Finding) { s.n++ }

func benchAddr(i int) netip.Addr {
	// 1.0.0.0/8: routable and outside every private range, so the detectors
	// treat it as an external source.
	return netip.AddrFrom4([4]byte{1, byte(i >> 16), byte(i >> 8), byte(i)})
}

// BenchmarkCountryBlockDistinctSources is the spoofed-SYN-flood shape: every
// packet carries a source the throttle map has never seen, so every packet
// touches the bound.
func BenchmarkCountryBlockDistinctSources(b *testing.B) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     func(netip.Addr) (string, bool) { return "RU", true },
		Blocked:    func(string) bool { return true },
		Empty:      func() bool { return false },
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return now })

	lan := netip.MustParseAddr("192.168.1.10")
	pkt := flow.Packet{DstIP: lan, SrcPort: 40000, DstPort: 22, Proto: model.ProtoTCP, SYN: true, Size: 60}

	// Fill the throttle map with sources that are all still inside the 30s
	// window, which is the state a botnet sweep reaches in seconds.
	const prefill = 12000
	for i := range prefill {
		p := pkt
		p.SrcIP = benchAddr(i)
		det.Observe(p)
	}

	b.ResetTimer()
	for i := range b.N {
		p := pkt
		p.SrcIP = benchAddr(prefill + i)
		det.Observe(p)
	}
}

// BenchmarkCountryBlockThrottledSource is the ordinary case — one source
// knocking repeatedly — and guards it against a regression paid for the flood.
func BenchmarkCountryBlockThrottledSource(b *testing.B) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     func(netip.Addr) (string, bool) { return "RU", true },
		Blocked:    func(string) bool { return true },
		Empty:      func() bool { return false },
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return now })

	pkt := flow.Packet{
		SrcIP: netip.MustParseAddr("91.209.108.172"), DstIP: netip.MustParseAddr("192.168.1.10"),
		SrcPort: 40000, DstPort: 22, Proto: model.ProtoTCP, SYN: true, Size: 60,
	}
	det.Observe(pkt)

	b.ResetTimer()
	for range b.N {
		det.Observe(pkt)
	}
}

// BenchmarkPortscanSynFlood is the case that never short-circuits: one source,
// one target, one port, at flood rate. Port and target diversity stay at 1, so
// no threshold is ever reached, firedAt is never set, and every packet used to
// re-derive both distinct counts over the whole attempt ring.
func BenchmarkPortscanSynFlood(b *testing.B) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	det := NewPortscan(PortscanConfig{
		Window:     time.Minute,
		External:   Thresholds{Ports: 15, Targets: 20},
		Internal:   Thresholds{Ports: 30, Targets: 40},
		Severity:   model.SeverityWarning,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return base })

	pkt := flow.Packet{
		SrcIP: netip.MustParseAddr("203.0.113.7"), DstIP: netip.MustParseAddr("192.168.1.10"),
		SrcPort: 40000, DstPort: 443, Proto: model.ProtoTCP, SYN: true, Size: 60, Time: base,
	}
	// Fill the per-source ring to its cap: a 10k pps flood reaches this in
	// under half a second and then stays there.
	for range 4096 {
		det.Observe(pkt)
	}

	b.ResetTimer()
	for range b.N {
		det.Observe(pkt)
	}
}

// BenchmarkPortscanSlidingScan is the opposite shape: a real scan with high
// target and port diversity, arriving steadily enough that the window is
// pruning on every packet. It guards the prune and bookkeeping paths, where a
// counter-based rewrite could give back what it won on the flood.
func BenchmarkPortscanSlidingScan(b *testing.B) {
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	det := NewPortscan(PortscanConfig{
		Window: time.Minute,
		// Above anything this benchmark reaches: measuring the evaluation
		// path, not the one finding it would otherwise produce.
		External:   Thresholds{Ports: 1 << 20, Targets: 1 << 20},
		Internal:   Thresholds{Ports: 1 << 20, Targets: 1 << 20},
		Severity:   model.SeverityWarning,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, &nopSink{}, func() time.Time { return base })

	src := netip.MustParseAddr("203.0.113.7")
	const step = 20 * time.Millisecond
	at := func(i int) flow.Packet {
		return flow.Packet{
			Time:  base.Add(time.Duration(i) * step),
			SrcIP: src,
			DstIP: netip.AddrFrom4([4]byte{192, 168, byte(i / 251), byte(i % 251)}),
			// Coprime with the target rotation so pairs do not repeat.
			SrcPort: 40000, DstPort: uint16(1 + i%1021),
			Proto: model.ProtoTCP, SYN: true, Size: 60,
		}
	}
	// 4096 attempts at 20ms span 82s — wider than the window, so the measured
	// packets each drop one attempt off the back as they add one to the front.
	const prefill = 4096
	for i := range prefill {
		det.Observe(at(i))
	}

	b.ResetTimer()
	for i := range b.N {
		det.Observe(at(prefill + i))
	}
}
