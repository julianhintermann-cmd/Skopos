package capture

import (
	"context"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// Source produces packets. The live AF_PACKET source and the demo generator
// both implement it, so the rest of the pipeline is identical whether traffic
// is real or synthetic.
type Source interface {
	// Run delivers packets to handle until ctx is cancelled or a fatal error
	// occurs. handle must not block for long; the aggregator's Add is cheap.
	Run(ctx context.Context, handle func(flow.Packet)) error
	// Name identifies the source for logs and the system view.
	Name() string
}
