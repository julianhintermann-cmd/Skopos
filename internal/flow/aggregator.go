package flow

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// FlowSink receives batches of completed flows. The store satisfies it.
type FlowSink interface {
	WriteFlows([]model.Flow) error
}

// Observer sees every packet in real time, before aggregation. Detectors
// implement it so scan/rate detection reacts immediately instead of waiting
// for the flush interval.
type Observer interface {
	Observe(Packet)
}

// entry accumulates one flow's counters between flushes. Counters are kept
// from the initiator's perspective: "out" is initiator→peer, "in" is the
// reverse.
type entry struct {
	k          key
	dir        model.Direction
	start      time.Time
	end        time.Time
	outBytes   uint64
	outPackets uint64
	inBytes    uint64
	inPackets  uint64
	dstName    string
}

// Aggregator batches packets into flow records and forwards each packet to an
// optional observer. It is safe for concurrent Add/Flush.
type Aggregator struct {
	classifier   *Classifier
	sink         FlowSink
	observer     Observer
	flush        time.Duration
	nameLookup   func(netip.Addr) string
	onFlushError func(error)

	mu    sync.Mutex
	flows map[key]*entry
}

// Config configures an Aggregator.
type Config struct {
	Classifier *Classifier
	Sink       FlowSink
	Observer   Observer // may be nil
	Flush      time.Duration
	// NameLookup resolves an address to a hostname learned from passive DNS,
	// filling in flows whose own packets carried no name. Optional.
	NameLookup func(netip.Addr) string
	// OnFlushError is called when a flush fails. The loop keeps running: a
	// full disk that later frees up should resume recording on its own, and
	// silently ending the only thing that writes history is the worst
	// available outcome. Optional.
	OnFlushError func(error)
}

// New creates an Aggregator.
func New(cfg Config) *Aggregator {
	if cfg.Flush <= 0 {
		cfg.Flush = 10 * time.Second
	}
	return &Aggregator{
		classifier:   cfg.Classifier,
		sink:         cfg.Sink,
		observer:     cfg.Observer,
		flush:        cfg.Flush,
		nameLookup:   cfg.NameLookup,
		onFlushError: cfg.OnFlushError,
		flows:        make(map[key]*entry),
	}
}

// Add records one packet: it is forwarded to the observer, then folded into
// the matching flow (creating it, or attaching to the reverse direction of an
// existing one).
func (a *Aggregator) Add(p Packet) {
	if a.observer != nil {
		a.observer.Observe(p)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	k := p.key()
	if e, ok := a.flows[k]; ok {
		e.addForward(p)
		return
	}
	if e, ok := a.flows[k.reverse()]; ok {
		e.addReverse(p)
		return
	}
	// New flow: this packet's source is the initiator.
	e := &entry{
		k:     k,
		dir:   a.classifier.Direction(p.SrcIP, p.DstIP),
		start: p.Time,
		end:   p.Time,
	}
	// Most flows carry no name of their own — the DNS lookup that resolved
	// the address happened in an earlier packet. Ask passive DNS.
	if p.DstName == "" && a.nameLookup != nil {
		e.dstName = a.nameLookup(p.DstIP)
	}
	e.addForward(p)
	a.flows[k] = e
}

func (e *entry) addForward(p Packet) {
	e.outBytes += p.Size
	e.outPackets++
	e.touch(p)
}

func (e *entry) addReverse(p Packet) {
	e.inBytes += p.Size
	e.inPackets++
	e.touch(p)
}

func (e *entry) touch(p Packet) {
	if p.Time.After(e.end) {
		e.end = p.Time
	}
	if e.dstName == "" && p.DstName != "" {
		e.dstName = p.DstName
	}
}

// Flush drains the accumulated flows into the sink and clears the table. Each
// call produces flow records covering at most one flush interval, which keeps
// the aggregator's memory bounded regardless of traffic.
func (a *Aggregator) Flush() error {
	a.mu.Lock()
	if len(a.flows) == 0 {
		a.mu.Unlock()
		return nil
	}
	batch := make([]model.Flow, 0, len(a.flows))
	for _, e := range a.flows {
		batch = append(batch, e.toModel())
	}
	a.flows = make(map[key]*entry)
	a.mu.Unlock()

	return a.sink.WriteFlows(batch)
}

func (e *entry) toModel() model.Flow {
	return model.Flow{
		Start:      e.start,
		End:        e.end,
		SrcIP:      e.k.srcIP,
		DstIP:      e.k.dstIP,
		SrcPort:    e.k.srcPort,
		DstPort:    e.k.dstPort,
		Proto:      e.k.proto,
		Dir:        e.dir,
		OutBytes:   e.outBytes,
		OutPackets: e.outPackets,
		InBytes:    e.inBytes,
		InPackets:  e.inPackets,
		DstName:    e.dstName,
	}
}

// Run flushes on the configured interval until ctx is cancelled, then does a
// final flush so in-flight flows are not lost on shutdown.
func (a *Aggregator) Run(ctx context.Context) error {
	t := time.NewTicker(a.flush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return a.Flush()
		case <-t.C:
			// A failed flush used to end the loop for good, so one full disk
			// meant nothing was recorded again until someone restarted the
			// process — even after the space came back. Keep ticking and
			// report, so recovery is automatic and the operator still hears
			// about it.
			if err := a.Flush(); err != nil {
				if a.onFlushError != nil {
					a.onFlushError(err)
				}
			}
		}
	}
}
