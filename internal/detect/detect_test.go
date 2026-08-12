package detect

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

type collector struct {
	mu       sync.Mutex
	findings []Finding
}

func (c *collector) Raise(f Finding) {
	c.mu.Lock()
	c.findings = append(c.findings, f)
	c.mu.Unlock()
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.findings)
}

func syn(t time.Time, src, dst string, dport uint16) flow.Packet {
	return flow.Packet{
		Time: t, SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		SrcPort: 40000, DstPort: dport, Proto: model.ProtoTCP, SYN: true, Size: 60,
	}
}

func TestPortscanVertical(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewPortscan(PortscanConfig{
		Window:   time.Minute,
		External: Thresholds{Ports: 15, Targets: 20},
		Internal: Thresholds{Ports: 30, Targets: 40},
		Severity: model.SeverityWarning,
		IsInternal: func(a netip.Addr) bool {
			return netip.MustParsePrefix("192.168.0.0/16").Contains(a)
		},
	}, c, func() time.Time { return base })

	// External source hits 15 distinct ports on one target → vertical scan.
	for port := uint16(1); port <= 15; port++ {
		d.Observe(syn(base.Add(time.Duration(port)*time.Second), "203.0.113.5", "192.168.1.10", port))
	}
	if c.count() != 1 {
		t.Fatalf("expected 1 vertical-scan finding, got %d", c.count())
	}
	if f := c.findings[0]; f.Detector != "portscan" || f.Source.String() != "203.0.113.5" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestPortscanHorizontal(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewPortscan(PortscanConfig{
		Window:     time.Minute,
		External:   Thresholds{Ports: 100, Targets: 20},
		Severity:   model.SeverityWarning,
		IsInternal: func(netip.Addr) bool { return false },
	}, c, func() time.Time { return base })

	// One port across 20 distinct targets → horizontal scan.
	for host := 1; host <= 20; host++ {
		dst := netip.AddrFrom4([4]byte{192, 168, 1, byte(host)}).String()
		d.Observe(syn(base.Add(time.Duration(host)*time.Second), "203.0.113.5", dst, 445))
	}
	if c.count() != 1 {
		t.Fatalf("expected 1 horizontal-scan finding, got %d", c.count())
	}
}

func TestPortscanInternalThresholdHigher(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewPortscan(PortscanConfig{
		Window:   time.Minute,
		External: Thresholds{Ports: 15, Targets: 20},
		Internal: Thresholds{Ports: 30, Targets: 40},
		Severity: model.SeverityWarning,
		IsInternal: func(a netip.Addr) bool {
			return netip.MustParsePrefix("192.168.0.0/16").Contains(a)
		},
	}, c, func() time.Time { return base })

	// An internal source hitting 20 ports must NOT trigger (internal
	// threshold is 30), where an external one would.
	for port := uint16(1); port <= 20; port++ {
		d.Observe(syn(base.Add(time.Duration(port)*time.Second), "192.168.1.50", "192.168.1.10", port))
	}
	if c.count() != 0 {
		t.Errorf("internal source below internal threshold should not fire, got %d", c.count())
	}
}

func TestPortscanFiresOncePerWindow(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewPortscan(PortscanConfig{
		Window:     time.Minute,
		External:   Thresholds{Ports: 15, Targets: 20},
		Severity:   model.SeverityWarning,
		IsInternal: func(netip.Addr) bool { return false },
	}, c, func() time.Time { return base })

	// 40 ports in the window: crosses the threshold but must fire only once.
	for port := uint16(1); port <= 40; port++ {
		d.Observe(syn(base.Add(time.Duration(port)*time.Millisecond), "203.0.113.5", "192.168.1.10", port))
	}
	if c.count() != 1 {
		t.Errorf("expected exactly 1 finding per window, got %d", c.count())
	}
}

func TestRateConnectionSpike(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewRate(RateConfig{
		Window:            10 * time.Second,
		MaxNewConnections: 100,
		Severity:          model.SeverityWarning,
	}, c, func() time.Time { return base })

	for i := 0; i < 100; i++ {
		d.Observe(syn(base.Add(time.Duration(i)*time.Millisecond), "203.0.113.9", "192.168.1.10", 443))
	}
	if c.count() != 1 {
		t.Fatalf("expected 1 rate finding, got %d", c.count())
	}
	if c.findings[0].Title != "Connection-rate spike" {
		t.Errorf("unexpected title: %s", c.findings[0].Title)
	}
}

func TestRateWindowExpiry(t *testing.T) {
	c := &collector{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	d := NewRate(RateConfig{
		Window:            10 * time.Second,
		MaxNewConnections: 50,
		Severity:          model.SeverityWarning,
	}, c, nil)

	// 40 connections spread over 20s (wider than the 10s window) should never
	// have 50 within any single window.
	for i := 0; i < 40; i++ {
		d.Observe(syn(base.Add(time.Duration(i)*500*time.Millisecond), "203.0.113.9", "192.168.1.10", 443))
	}
	if c.count() != 0 {
		t.Errorf("connections spread beyond the window should not trip the threshold, got %d", c.count())
	}
}
