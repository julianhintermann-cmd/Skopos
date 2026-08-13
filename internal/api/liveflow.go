package api

import (
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// LiveFlow is the wire shape for a completed flow shown in the live view. It is
// a flattened, JSON-tagged projection of model.Flow so the dashboard contract
// does not depend on the domain type's field names, and it carries the
// bidirectional totals the table shows (which are methods, not fields, on the
// model).
type LiveFlow struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	SrcPort uint16    `json:"src_port"`
	DstPort uint16    `json:"dst_port"`
	Proto   string    `json:"proto"`
	Dir     string    `json:"dir"`
	Bytes   uint64    `json:"bytes"`
	Packets uint64    `json:"packets"`
	DstName string    `json:"dst_name,omitempty"`
	// Blocked marks a flow the kernel is dropping. The capture tap sees such
	// packets before netfilter discards them, so they still appear here —
	// flagged, so the view can say "arriving, but dropped".
	Blocked bool `json:"blocked,omitempty"`
}

// NewLiveFlow projects a model.Flow onto the wire shape. blocked decides the
// Blocked flag from the whole flow (per-IP blocks match either endpoint;
// country coverage only inbound-initiated flows) and may be nil.
func NewLiveFlow(f model.Flow, blocked func(model.Flow) bool) LiveFlow {
	lf := LiveFlow{
		Start:   f.Start,
		End:     f.End,
		Src:     f.SrcIP.String(),
		Dst:     f.DstIP.String(),
		SrcPort: f.SrcPort,
		DstPort: f.DstPort,
		Proto:   f.Proto.String(),
		Dir:     string(f.Dir),
		Bytes:   f.Bytes(),
		Packets: f.Packets(),
		DstName: f.DstName,
	}
	if blocked != nil && blocked(f) {
		lf.Blocked = true
	}
	return lf
}

// NewLiveFlows projects a batch, preserving order. blocked may be nil.
func NewLiveFlows(flows []model.Flow, blocked func(model.Flow) bool) []LiveFlow {
	out := make([]LiveFlow, len(flows))
	for i, f := range flows {
		out[i] = NewLiveFlow(f, blocked)
	}
	return out
}

// LiveFlowProvider supplies the most recently completed flows so a freshly
// opened live view starts populated instead of waiting for the next flush.
type LiveFlowProvider interface {
	RecentFlows() []LiveFlow
}
