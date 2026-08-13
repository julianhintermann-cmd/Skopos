package detect

import (
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

func TestBaselineFiresOnlyOnRealDepartures(t *testing.T) {
	var findings []Finding
	lan := netip.MustParseAddr("192.168.1.30")
	wan := netip.MustParseAddr("203.0.113.1")
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)

	det := NewBaseline(BaselineConfig{
		Bucket: time.Hour, History: 24, MinBuckets: 3, Factor: 8, MinBytes: 1 << 20,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), func() time.Time { return now })

	send := func(at time.Time, bytes uint64) {
		det.Observe(flow.Packet{Time: at, SrcIP: lan, DstIP: wan, Size: bytes})
	}

	// Six quiet hours of about 2 MiB each.
	for h := 0; h < 6; h++ {
		send(now.Add(time.Duration(h)*time.Hour+time.Minute), 2<<20)
	}
	if len(findings) != 0 {
		t.Fatalf("a steady device must not alert: %+v", findings)
	}

	// Hour six sends 100 MiB, then hour seven closes it.
	send(now.Add(6*time.Hour+time.Minute), 100<<20)
	send(now.Add(7*time.Hour+time.Minute), 1<<20)

	if len(findings) != 1 {
		t.Fatalf("expected one finding for the spike, got %+v", findings)
	}
	f := findings[0]
	if f.Detector != "baseline" || f.Source != lan {
		t.Errorf("finding = %+v", f)
	}
	// Unusual is not malicious: never auto-block on this signal.
	if f.SuggestBlock {
		t.Error("the baseline detector must never suggest a block")
	}
}

func TestBaselineNeedsHistoryAndAFloor(t *testing.T) {
	var findings []Finding
	lan := netip.MustParseAddr("192.168.1.31")
	wan := netip.MustParseAddr("203.0.113.1")
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	det := NewBaseline(BaselineConfig{
		Bucket: time.Hour, MinBuckets: 5, Factor: 4, MinBytes: 10 << 20,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), func() time.Time { return now })

	// A huge second hour, but with almost no history: silence.
	det.Observe(flow.Packet{Time: now, SrcIP: lan, DstIP: wan, Size: 1 << 20})
	det.Observe(flow.Packet{Time: now.Add(time.Hour), SrcIP: lan, DstIP: wan, Size: 500 << 20})
	det.Observe(flow.Packet{Time: now.Add(2 * time.Hour), SrcIP: lan, DstIP: wan, Size: 1})
	if len(findings) != 0 {
		t.Fatalf("must not judge without enough history: %+v", findings)
	}

	// Enough history, but the spike is below the byte floor: still silence.
	det2 := NewBaseline(BaselineConfig{
		Bucket: time.Hour, MinBuckets: 2, Factor: 2, MinBytes: 100 << 20,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), func() time.Time { return now })
	for h := 0; h < 5; h++ {
		det2.Observe(flow.Packet{Time: now.Add(time.Duration(h) * time.Hour), SrcIP: lan, DstIP: wan, Size: 1024})
	}
	det2.Observe(flow.Packet{Time: now.Add(5 * time.Hour), SrcIP: lan, DstIP: wan, Size: 1 << 20})
	det2.Observe(flow.Packet{Time: now.Add(6 * time.Hour), SrcIP: lan, DstIP: wan, Size: 1})
	if len(findings) != 0 {
		t.Errorf("a small absolute volume must not alert: %+v", findings)
	}
}

func TestBaselineIgnoresInboundAndWANSources(t *testing.T) {
	var findings []Finding
	det := NewBaseline(BaselineConfig{
		Bucket: time.Hour, MinBuckets: 1, Factor: 2, MinBytes: 1,
		IsInternal: func(a netip.Addr) bool { return a.IsPrivate() },
	}, SinkFunc(func(f Finding) { findings = append(findings, f) }), time.Now)

	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	// WAN → LAN is not this device's doing.
	for h := 0; h < 5; h++ {
		det.Observe(flow.Packet{
			Time:  now.Add(time.Duration(h) * time.Hour),
			SrcIP: netip.MustParseAddr("203.0.113.1"), DstIP: netip.MustParseAddr("192.168.1.30"),
			Size: 900 << 20,
		})
	}
	// LAN → LAN is local business.
	for h := 0; h < 5; h++ {
		det.Observe(flow.Packet{
			Time:  now.Add(time.Duration(h) * time.Hour),
			SrcIP: netip.MustParseAddr("192.168.1.30"), DstIP: netip.MustParseAddr("192.168.1.40"),
			Size: 900 << 20,
		})
	}
	if len(findings) != 0 {
		t.Errorf("only outbound WAN traffic counts: %+v", findings)
	}
	if det.Devices() != 0 {
		t.Errorf("no device baseline should exist, got %d", det.Devices())
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []uint64
		want uint64
	}{
		{nil, 0},
		{[]uint64{5}, 5},
		{[]uint64{3, 1, 2}, 2},
		{[]uint64{4, 1, 3, 2}, 2}, // (2+3)/2
		{[]uint64{10, 10, 10}, 10},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Errorf("median(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
