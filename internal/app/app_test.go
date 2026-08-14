package app

import (
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// captureUp is a sample-state source reporting one healthy capture source, so
// the meter's rates count as measurements rather than as the absence of one.
func captureUp() flow.SampleState {
	return flow.SampleState{
		KeepRate: 1, Capture: flow.CaptureUp, SourcesUp: 1, SourcesTotal: 1,
	}
}

func TestLiveMeterComputesRate(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newLiveMeter(func() time.Time { return now }, captureUp)

	// 1000 packets of 100 bytes each.
	for i := 0; i < 1000; i++ {
		m.Observe(flow.Packet{Size: 100})
	}
	now = now.Add(time.Second)
	st := m.Snapshot()

	// 100000 bytes/s = 800000 bits/s; 1000 packets/s.
	if st.BitsPerSecond == nil || st.PacketsPerSecond == nil {
		t.Fatalf("capture is up: rates must be reported, got %+v", st)
	}
	if *st.BitsPerSecond < 790000 || *st.BitsPerSecond > 810000 {
		t.Errorf("bits/s = %.0f, want ~800000", *st.BitsPerSecond)
	}
	if *st.PacketsPerSecond < 990 || *st.PacketsPerSecond > 1010 {
		t.Errorf("packets/s = %.0f, want ~1000", *st.PacketsPerSecond)
	}
}

func TestResolveInterfacesPassesThroughExplicit(t *testing.T) {
	out := resolveInterfaces([]string{"eth0", "eth1"})
	if len(out) != 2 || out[0] != "eth0" || out[1] != "eth1" {
		t.Errorf("explicit interfaces changed: %v", out)
	}
}

func TestParsePrefixAcceptsIPAndCIDR(t *testing.T) {
	p, err := parsePrefix("203.0.113.5")
	if err != nil || p.Bits() != 32 {
		t.Errorf("bare IP → %v (%v), want /32", p, err)
	}
	p, err = parsePrefix("203.0.113.0/24")
	if err != nil || p.Bits() != 24 {
		t.Errorf("CIDR → %v (%v), want /24", p, err)
	}
	if _, err := parsePrefix("not-an-ip"); err == nil {
		t.Error("garbage should error")
	}
}

func TestClockToTime(t *testing.T) {
	tm := clockToTime(config.ClockTime{Hour: 23, Minute: 30})
	if tm.Hour() != 23 || tm.Minute() != 30 {
		t.Errorf("clockToTime = %02d:%02d", tm.Hour(), tm.Minute())
	}
}

func TestResolveGatewayNeverPanics(t *testing.T) {
	// Whatever the host looks like, this must return a (possibly invalid)
	// Addr without panicking, and any parsed gateway is a v4 address.
	gw := resolveGateway()
	if gw.IsValid() && !gw.Is4() {
		t.Errorf("unexpected gateway family: %v", gw)
	}
}
