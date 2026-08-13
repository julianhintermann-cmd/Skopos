package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

func TestCountryBlockRaisesForInboundOnly(t *testing.T) {
	var findings []Finding
	blocked := map[string]bool{"RU": true}
	internal := func(a netip.Addr) bool { return a.IsPrivate() }
	lookup := func(a netip.Addr) (string, bool) {
		if a == netip.MustParseAddr("91.209.108.172") {
			return "RU", true
		}
		return "US", true
	}
	now := time.Unix(1000, 0)
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     lookup,
		Blocked:    func(c string) bool { return blocked[c] },
		Empty:      func() bool { return len(blocked) == 0 },
		IsInternal: internal,
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), func() time.Time { return now })

	ru := netip.MustParseAddr("91.209.108.172")
	lan := netip.MustParseAddr("192.168.1.10")

	// Inbound connection attempt from a blocked country → finding with
	// SuggestBlock.
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 22, SYN: true})
	if len(findings) != 1 || !findings[0].SuggestBlock || findings[0].Detector != "country" {
		t.Fatalf("findings = %+v", findings)
	}

	// Same source again within the throttle window → no second finding.
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 23, SYN: true})
	if len(findings) != 1 {
		t.Fatalf("throttle failed, findings = %d", len(findings))
	}
	// After the throttle expires it raises again.
	now = now.Add(time.Minute)
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 24, SYN: true})
	if len(findings) != 2 {
		t.Fatalf("expected re-raise after throttle, got %d", len(findings))
	}

	// A non-SYN inbound packet is reply traffic of a connection the LAN
	// opened itself (conntrack lets it through deliberately) — never raised.
	now = now.Add(time.Minute)
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, SrcPort: 443, DstPort: 43978})
	if len(findings) != 2 {
		t.Fatalf("reply traffic must not raise, findings = %d", len(findings))
	}

	// Outbound to a blocked country is NOT blocked (your own traffic).
	det.Observe(flow.Packet{SrcIP: lan, DstIP: ru, DstPort: 443, SYN: true})
	// Inbound from a non-blocked country is fine.
	det.Observe(flow.Packet{SrcIP: netip.MustParseAddr("8.8.8.8"), DstIP: lan, SYN: true})
	if len(findings) != 2 {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	// Empty list short-circuits.
	blocked = map[string]bool{}
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, SYN: true})
	if len(findings) != 2 {
		t.Error("empty blocklist must observe nothing")
	}
}

func TestCountryBlockStaysSilentWhenKernelCovers(t *testing.T) {
	var findings []Finding
	ru := netip.MustParseAddr("91.209.108.172")
	lan := netip.MustParseAddr("192.168.1.10")
	det := NewCountryBlock(CountryBlockConfig{
		Lookup:     func(netip.Addr) (string, bool) { return "RU", true },
		Blocked:    func(string) bool { return true },
		Empty:      func() bool { return false },
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
		Covered:    func(a netip.Addr) bool { return a == ru },
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), func() time.Time { return time.Unix(1000, 0) })

	// The preventive sets already drop this source — no alert, no re-block.
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 22, SYN: true})
	if len(findings) != 0 {
		t.Fatalf("covered source must stay silent, findings = %+v", findings)
	}
	// An uncovered source (e.g. the database just updated) still raises.
	det.Observe(flow.Packet{SrcIP: netip.MustParseAddr("91.209.109.9"), DstIP: lan, DstPort: 22, SYN: true})
	if len(findings) != 1 {
		t.Fatalf("uncovered source must raise, findings = %d", len(findings))
	}
}
