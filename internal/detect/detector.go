// Package detect turns the packet and event stream into findings: port
// scans, connection-rate anomalies, blocklist hits and new devices. Detectors
// are deliberately mechanical — thresholds come from config — and hand
// findings to the policy layer, which owns severity, throttling and any
// resulting action.
package detect

import (
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Finding is a raw detection, before policy decides severity, throttling or
// action. Detectors fill Detector, Source, Title and Detail; the suggested
// severity comes from that detector's configuration.
type Finding struct {
	Detector string
	Source   netip.Addr
	Severity model.Severity
	Title    string
	Detail   string
	// SuggestBlock is true when this detector is configured to auto-block the
	// source. The policy layer still decides whether enforcement is on.
	SuggestBlock bool
}

// Sink receives findings from detectors.
type Sink interface {
	Raise(Finding)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(Finding)

// Raise implements Sink.
func (f SinkFunc) Raise(finding Finding) { f(finding) }

// Clock supplies the current time; detectors take one so their sliding
// windows are deterministic under test.
type Clock func() time.Time
