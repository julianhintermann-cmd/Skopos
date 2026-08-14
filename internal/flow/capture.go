package flow

import (
	"sort"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// CaptureStatus is what the capture pipeline is doing right now. It is a fact
// about the process, asserted by the goroutines that own the sources — never
// inferred from silence, because "no packets for four minutes" and "capture is
// down" are different claims and only one of them is ours to make.
type CaptureStatus string

const (
	// CaptureStarting is the window before any source has reported. It is
	// distinct from CaptureDown so a restart does not raise a false alarm.
	CaptureStarting CaptureStatus = "starting"
	CaptureUp       CaptureStatus = "up"
	// CapturePartial is some sources alive and some not: a multi-interface
	// capture that loses one NIC still sees half the network, and the operator
	// needs to see that as half.
	CapturePartial CaptureStatus = "partial"
	CaptureDown    CaptureStatus = "down"
)

// coverageBucket is the interval every coverage record is truncated to. The
// coarser rollups accumulate from these, exactly as the flow rollups do, so
// retention and the query path need no special case.
const coverageBucket = time.Minute

// captureBucket accumulates one interval of coverage in memory before it is
// drained to the sink.
type captureBucket struct {
	sourcesTotal    int
	sourcesUp       int
	observedPackets uint64
	keptPackets     uint64
	secondsCovered  int
}

// CaptureHealth is the registry of capture sources plus the accumulator for
// the coverage heartbeat. One instance is shared by the capture loop — which
// registers the sources and ticks it once a second — and the aggregator, which
// drains it to the store on every flush whether or not any flow was written.
// That last part is what makes a genuinely quiet minute a recorded measurement
// instead of a hole indistinguishable from a dead capture.
//
// It is safe for concurrent use.
type CaptureHealth struct {
	mu      sync.Mutex
	sources map[string]bool // name → alive
	started bool            // at least one source has reported alive
	buckets map[int64]*captureBucket
}

// NewCaptureHealth creates an empty registry. Until a source reports, the
// status is "starting": nothing has been claimed either way.
func NewCaptureHealth() *CaptureHealth {
	return &CaptureHealth{
		sources: make(map[string]bool),
		buckets: make(map[int64]*captureBucket),
	}
}

// Register declares a configured source before it starts. Registering up front
// is what makes sources_total right from the first heartbeat, so a source that
// never manages to open its interface reads as configured-and-down rather than
// as never having existed.
func (h *CaptureHealth) Register(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.sources[name]; !ok {
		h.sources[name] = false
	}
}

// Up records that a source's read loop is running.
func (h *CaptureHealth) Up(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sources[name] = true
	h.started = true
}

// Down records that a source's read loop has returned — from a fatal error or
// from an ordinary shutdown; the coverage record claims only that the source
// is no longer capturing. The next heartbeat folds it into the current bucket,
// which is at most one second away.
func (h *CaptureHealth) Down(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sources[name] = false
}

// CaptureState is the registry's answer at a point in time.
type CaptureState struct {
	Status       CaptureStatus
	SourcesUp    int
	SourcesTotal int
}

// State reports current source liveness.
func (h *CaptureHealth) State() CaptureState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state()
}

func (h *CaptureHealth) state() CaptureState {
	st := CaptureState{SourcesTotal: len(h.sources)}
	for _, alive := range h.sources {
		if alive {
			st.SourcesUp++
		}
	}
	switch {
	case !h.started || st.SourcesTotal == 0:
		st.Status = CaptureStarting
	case st.SourcesUp == 0:
		st.Status = CaptureDown
	case st.SourcesUp < st.SourcesTotal:
		st.Status = CapturePartial
	default:
		st.Status = CaptureUp
	}
	return st
}

// Tick credits one heartbeat to the bucket containing now and folds in the
// sampler's counts for the second just closed. The caller drives it from a
// fixed 1 Hz timer rather than from the packet path, so a minute with no
// traffic still accumulates sixty covered seconds.
func (h *CaptureHealth) Tick(now time.Time, w Window) {
	h.mu.Lock()
	defer h.mu.Unlock()

	live := h.state()
	ms := now.UTC().Truncate(coverageBucket).UnixMilli()
	b, ok := h.buckets[ms]
	if !ok {
		b = &captureBucket{sourcesTotal: live.SourcesTotal, sourcesUp: live.SourcesUp}
		h.buckets[ms] = b
	}

	b.observedPackets += w.Observed
	b.keptPackets += w.Kept
	// A window with no elapsed time measured no wall-clock second, but its
	// packets were still counted and must not be thrown away.
	if w.Elapsed > 0 {
		b.secondsCovered++
	}
	if live.SourcesTotal > b.sourcesTotal {
		b.sourcesTotal = live.SourcesTotal
	}
	// sources_up is the minimum across the bucket, which is what "alive for
	// the whole bucket" means: one NIC dropping for ten seconds makes the
	// whole minute partial rather than averaging away.
	if live.SourcesUp < b.sourcesUp {
		b.sourcesUp = live.SourcesUp
	}
}

// Drain returns every accumulated bucket, oldest first, and clears them. The
// still-open bucket is included: the store accumulates repeated writes for the
// same bucket, so a minute is assembled from however many flushes fall inside
// it and seconds_covered adds up to the truth.
func (h *CaptureHealth) Drain() []model.Coverage {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buckets) == 0 {
		return nil
	}
	out := make([]model.Coverage, 0, len(h.buckets))
	for ms, b := range h.buckets {
		out = append(out, model.Coverage{
			Bucket:          time.UnixMilli(ms).UTC(),
			SourcesTotal:    b.sourcesTotal,
			SourcesUp:       b.sourcesUp,
			ObservedPackets: b.observedPackets,
			KeptPackets:     b.keptPackets,
			SecondsCovered:  b.secondsCovered,
		})
	}
	h.buckets = make(map[int64]*captureBucket)
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket.Before(out[j].Bucket) })
	return out
}
