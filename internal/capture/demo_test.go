package capture

import (
	"context"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestDemoStepEmitsTraffic(t *testing.T) {
	d := NewDemoSource(DemoOptions{Seed: 1, Now: func() time.Time { return time.Unix(1000, 0) }})
	var pkts []flow.Packet
	d.Step(func(p flow.Packet) { pkts = append(pkts, p) })

	if len(pkts) == 0 {
		t.Fatal("demo step emitted no packets")
	}
	// Baseline traffic comes in request/reply pairs, so the count is even and
	// small.
	if len(pkts)%2 != 0 {
		t.Errorf("baseline packets should come in pairs, got %d", len(pkts))
	}
	for _, p := range pkts {
		if !p.SrcIP.IsValid() || !p.DstIP.IsValid() {
			t.Errorf("packet has invalid address: %+v", p)
		}
	}
}

func TestDemoInjectsPortScan(t *testing.T) {
	d := NewDemoSource(DemoOptions{Seed: 1, Now: func() time.Time { return time.Unix(1000, 0) }})

	// Drive enough steps to pass the scan injection point (tick%40==12) and
	// collect packets from that specific step.
	var scanStepPkts []flow.Packet
	for i := 0; i < 40; i++ {
		var step []flow.Packet
		d.Step(func(p flow.Packet) { step = append(step, p) })
		if d.ticks%40 == 12 {
			scanStepPkts = step
		}
	}

	// Count SYNs to a single target across many low ports from one source.
	byTarget := map[string]map[uint16]bool{}
	for _, p := range scanStepPkts {
		if p.Proto == model.ProtoTCP && p.SYN && p.DstPort <= 30 {
			if byTarget[p.DstIP.String()] == nil {
				byTarget[p.DstIP.String()] = map[uint16]bool{}
			}
			byTarget[p.DstIP.String()][p.DstPort] = true
		}
	}
	found := false
	for _, ports := range byTarget {
		if len(ports) >= 20 {
			found = true
		}
	}
	if !found {
		t.Error("expected a port-scan burst (>=20 distinct low ports to one target) on the scan step")
	}
}

func TestDemoRunStopsOnContextCancel(t *testing.T) {
	d := NewDemoSource(DemoOptions{Seed: 1, Step: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, func(flow.Packet) {}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancel")
	}
}
