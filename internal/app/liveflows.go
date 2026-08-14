package app

import (
	"sort"
	"sync"

	"github.com/julianhintermann-cmd/skopos/internal/api"
	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// eventPublisher is the subset of the API's SSE hub the live stream needs.
type eventPublisher interface {
	Publish(api.Event)
}

// liveRingSize bounds how many recent flows the live view can back-fill on
// connect. A few hundred covers the visible table with room to spare; older
// flows live in the store and are reached through the Traffic view.
const liveRingSize = 400

// liveFlows decorates a flow.FlowSink: every flushed batch is still written to
// the wrapped sink (the store), and is additionally projected for the live
// view — pushed to connected dashboards over SSE and kept in a bounded ring so
// a freshly opened live view starts populated instead of waiting for the next
// flush. It satisfies flow.FlowSink and api.LiveFlowProvider.
type liveFlows struct {
	next    flow.FlowSink
	hub     eventPublisher
	blocked func(model.Flow) bool // may be nil

	mu   sync.Mutex
	ring []api.LiveFlow // newest last
}

func newLiveFlows(next flow.FlowSink, hub eventPublisher, blocked func(model.Flow) bool) *liveFlows {
	return &liveFlows{next: next, hub: hub, blocked: blocked, ring: make([]api.LiveFlow, 0, liveRingSize)}
}

// WriteFlows records the live projection first (so the live view reflects
// observed traffic even if the durable write later fails), publishes it, then
// forwards the batch to the wrapped sink.
func (l *liveFlows) WriteFlows(flows []model.Flow) error {
	if len(flows) > 0 {
		batch := api.NewLiveFlows(flows, l.blocked)

		l.mu.Lock()
		l.ring = append(l.ring, batch...)
		if over := len(l.ring) - liveRingSize; over > 0 {
			l.ring = l.ring[over:]
		}
		l.mu.Unlock()

		if l.hub != nil {
			l.hub.Publish(api.Event{Type: "flows", Data: batch})
		}
	}
	return l.next.WriteFlows(flows)
}

// WriteCoverage implements flow.FlowSink. The live view shows flows, not
// coverage, so the heartbeat passes straight through.
func (l *liveFlows) WriteCoverage(cov []model.Coverage) error {
	return l.next.WriteCoverage(cov)
}

// RecentFlows returns the retained flows newest-first for the initial snapshot.
func (l *liveFlows) RecentFlows() []api.LiveFlow {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]api.LiveFlow, len(l.ring))
	copy(out, l.ring)
	sort.Slice(out, func(i, j int) bool { return out[i].End.After(out[j].End) })
	return out
}
