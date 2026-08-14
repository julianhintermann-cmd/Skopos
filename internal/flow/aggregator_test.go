package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

type captureSink struct {
	mu       sync.Mutex
	flows    []model.Flow
	coverage []model.Coverage
}

func (c *captureSink) WriteFlows(f []model.Flow) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flows = append(c.flows, f...)
	return nil
}

func (c *captureSink) WriteCoverage(cov []model.Coverage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.coverage = append(c.coverage, cov...)
	return nil
}

type countObserver struct {
	mu    sync.Mutex
	count int
}

func (o *countObserver) Observe(Packet) {
	o.mu.Lock()
	o.count++
	o.mu.Unlock()
}

func defaultClassifier() *Classifier {
	return NewClassifier([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"})
}

func pkt(t time.Time, src, dst string, sp, dp uint16, size uint64) Packet {
	return Packet{
		Time: t, SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		SrcPort: sp, DstPort: dp, Proto: model.ProtoTCP, Size: size,
	}
}

func TestAggregatorPairsBidirectional(t *testing.T) {
	sink := &captureSink{}
	obs := &countObserver{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	a := New(Config{Classifier: defaultClassifier(), Sink: sink, Observer: obs})

	// Outbound request and its reply must fold into ONE flow with both
	// directions populated.
	a.Add(pkt(base, "192.168.1.10", "9.9.9.9", 40000, 443, 100))
	reply := pkt(base.Add(time.Millisecond), "9.9.9.9", "192.168.1.10", 443, 40000, 1400)
	a.Add(reply)

	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(sink.flows) != 1 {
		t.Fatalf("got %d flows, want 1 (request+reply paired)", len(sink.flows))
	}
	f := sink.flows[0]
	if f.OutBytes != 100 || f.InBytes != 1400 {
		t.Errorf("out=%d in=%d, want out=100 in=1400", f.OutBytes, f.InBytes)
	}
	if f.Dir != model.DirLANtoWAN {
		t.Errorf("direction = %s, want lan_wan", f.Dir)
	}
	if f.SrcIP.String() != "192.168.1.10" {
		t.Errorf("initiator = %s, want 192.168.1.10", f.SrcIP)
	}
	if obs.count != 2 {
		t.Errorf("observer saw %d packets, want 2", obs.count)
	}
}

func TestAggregatorFlushClears(t *testing.T) {
	sink := &captureSink{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	a := New(Config{Classifier: defaultClassifier(), Sink: sink})

	a.Add(pkt(base, "192.168.1.10", "9.9.9.9", 40000, 443, 100))
	_ = a.Flush()
	_ = a.Flush() // second flush must be a no-op, not a duplicate

	if len(sink.flows) != 1 {
		t.Errorf("got %d flows across two flushes, want 1", len(sink.flows))
	}
}

func TestAggregatorSeparatesDistinctFlows(t *testing.T) {
	sink := &captureSink{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	a := New(Config{Classifier: defaultClassifier(), Sink: sink})

	a.Add(pkt(base, "192.168.1.10", "9.9.9.9", 40000, 443, 100))
	a.Add(pkt(base, "192.168.1.10", "9.9.9.9", 40001, 443, 100)) // different src port
	a.Add(pkt(base, "192.168.1.11", "1.1.1.1", 40000, 53, 100))
	_ = a.Flush()

	if len(sink.flows) != 3 {
		t.Errorf("got %d flows, want 3 distinct", len(sink.flows))
	}
}

// A flush with no flows used to write nothing at all, which is precisely why a
// quiet minute and a dead capture were indistinguishable afterwards. The
// coverage heartbeat must land either way.
func TestFlushWritesCoverageWithoutAnyFlows(t *testing.T) {
	sink := &captureSink{}
	a := New(Config{Classifier: defaultClassifier(), Sink: sink})
	h := NewCaptureHealth()
	h.Register("eth0")
	h.Up("eth0")
	a.SetCaptureHealth(h)

	h.Tick(time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC), Window{Elapsed: time.Second})
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(sink.flows) != 0 {
		t.Errorf("wrote %d flows, want none", len(sink.flows))
	}
	if len(sink.coverage) != 1 {
		t.Fatalf("wrote %d coverage records, want 1 — a quiet interval must still be recorded", len(sink.coverage))
	}
	if sink.coverage[0].SourcesUp != 1 {
		t.Errorf("sources_up = %d, want 1", sink.coverage[0].SourcesUp)
	}
}

// With nothing at all to report the flush stays a no-op, so an idle aggregator
// does not write a row per tick.
func TestFlushWithoutFlowsOrCoverageIsANoOp(t *testing.T) {
	sink := &captureSink{}
	a := New(Config{Classifier: defaultClassifier(), Sink: sink})
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(sink.flows) != 0 || len(sink.coverage) != 0 {
		t.Errorf("idle flush wrote flows=%d coverage=%d, want nothing", len(sink.flows), len(sink.coverage))
	}
}

// The measured floor and the coverage that qualifies it must arrive together;
// a flow batch without its coverage is a byte count nobody can interpret.
func TestFlushWritesFlowsWithTheirCoverage(t *testing.T) {
	sink := &captureSink{}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	a := New(Config{Classifier: defaultClassifier(), Sink: sink})
	h := NewCaptureHealth()
	h.Register("eth0")
	h.Up("eth0")
	a.SetCaptureHealth(h)

	a.Add(pkt(base, "192.168.1.10", "9.9.9.9", 40000, 443, 100))
	h.Tick(base, Window{Observed: 1000, Kept: 100, Elapsed: time.Second})
	if err := a.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(sink.flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(sink.flows))
	}
	if len(sink.coverage) != 1 {
		t.Fatalf("got %d coverage records, want 1", len(sink.coverage))
	}
	c := sink.coverage[0]
	if c.ObservedPackets != 1000 || c.KeptPackets != 100 {
		t.Errorf("observed=%d kept=%d, want 1000/100 (a 1:10 keep rate)", c.ObservedPackets, c.KeptPackets)
	}
}

func TestClassifierDirection(t *testing.T) {
	c := defaultClassifier()
	cases := []struct {
		src, dst string
		want     model.Direction
	}{
		{"192.168.1.10", "9.9.9.9", model.DirLANtoWAN},
		{"9.9.9.9", "192.168.1.10", model.DirWANtoLAN},
		{"192.168.1.10", "192.168.1.20", model.DirLANtoLAN},
		{"8.8.8.8", "9.9.9.9", model.DirWANtoWAN},
	}
	for _, tc := range cases {
		got := c.Direction(netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst))
		if got != tc.want {
			t.Errorf("Direction(%s→%s) = %s, want %s", tc.src, tc.dst, got, tc.want)
		}
	}
}
