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

	// Inbound from a blocked country → finding with SuggestBlock.
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 22})
	if len(findings) != 1 || !findings[0].SuggestBlock || findings[0].Detector != "country" {
		t.Fatalf("findings = %+v", findings)
	}

	// Same source again within the throttle window → no second finding.
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 23})
	if len(findings) != 1 {
		t.Fatalf("throttle failed, findings = %d", len(findings))
	}
	// After the throttle expires it raises again.
	now = now.Add(time.Minute)
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan, DstPort: 24})
	if len(findings) != 2 {
		t.Fatalf("expected re-raise after throttle, got %d", len(findings))
	}

	// Outbound to a blocked country is NOT blocked (your own traffic).
	det.Observe(flow.Packet{SrcIP: lan, DstIP: ru, DstPort: 443})
	// Inbound from a non-blocked country is fine.
	det.Observe(flow.Packet{SrcIP: netip.MustParseAddr("8.8.8.8"), DstIP: lan})
	if len(findings) != 2 {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	// Empty list short-circuits.
	blocked = map[string]bool{}
	det.Observe(flow.Packet{SrcIP: ru, DstIP: lan})
	if len(findings) != 2 {
		t.Error("empty blocklist must observe nothing")
	}
}
