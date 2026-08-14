package app

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// domainRecorder accumulates "which device talked to which domain" from the
// completed flows, rolled up per hour. It decorates a flow sink rather than
// observing packets: a flow already knows its total bytes and its resolved
// name, so one row per device/domain/hour replaces thousands of packets.
type domainRecorder struct {
	next       flow.FlowSink
	store      *store.Store
	isInternal func(netip.Addr) bool
	log        func(string, ...any)

	mu   sync.Mutex
	pend map[contactKey]*store.DomainContact
}

type contactKey struct {
	hourMs int64
	device string
	name   string
}

func newDomainRecorder(next flow.FlowSink, st *store.Store, isInternal func(netip.Addr) bool, log func(string, ...any)) *domainRecorder {
	return &domainRecorder{
		next:       next,
		store:      st,
		isInternal: isInternal,
		log:        log,
		pend:       map[contactKey]*store.DomainContact{},
	}
}

// WriteFlows implements flow.FlowSink.
func (d *domainRecorder) WriteFlows(flows []model.Flow) error {
	d.mu.Lock()
	for _, f := range flows {
		if f.DstName == "" {
			continue
		}
		// Attribute to the LAN endpoint: for outbound flows that is the
		// source, for inbound the destination.
		device := f.SrcIP
		if !d.isInternal(device) {
			device = f.DstIP
		}
		if !d.isInternal(device) {
			continue // WAN-to-WAN, nothing of ours to attribute
		}
		k := contactKey{
			hourMs: f.Start.Truncate(time.Hour).UnixMilli(),
			device: device.String(),
			name:   f.DstName,
		}
		c := d.pend[k]
		if c == nil {
			c = &store.DomainContact{HourMs: k.hourMs, DeviceIP: k.device, Name: k.name}
			d.pend[k] = c
		}
		c.Flows++
		c.Bytes += int64(f.Bytes())
	}
	d.mu.Unlock()

	return d.next.WriteFlows(flows)
}

// WriteCoverage implements flow.FlowSink. Domain contacts are derived from
// flows, so the coverage heartbeat passes straight through.
func (d *domainRecorder) WriteCoverage(cov []model.Coverage) error {
	return d.next.WriteCoverage(cov)
}

// Run persists the accumulated contacts on an interval.
func (d *domainRecorder) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.flush(context.WithoutCancel(ctx))
			return
		case <-t.C:
			d.flush(ctx)
		}
	}
}

func (d *domainRecorder) flush(ctx context.Context) {
	d.mu.Lock()
	batch := make([]store.DomainContact, 0, len(d.pend))
	for _, c := range d.pend {
		batch = append(batch, *c)
	}
	d.pend = map[contactKey]*store.DomainContact{}
	d.mu.Unlock()

	if err := d.store.AddDomainContacts(ctx, batch); err != nil {
		d.log("domains: persisting %d contacts: %v", len(batch), err)
	}
}
