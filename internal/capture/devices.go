package capture

import (
	"context"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
)

// DeviceStore persists device sightings and reports whether a device is new.
type DeviceStore interface {
	UpsertDevice(ctx context.Context, mac, ip, hostname, vendor string) (isNew bool, err error)
}

// NewDeviceFunc is called once when a previously-unseen device appears, so the
// detection layer can raise a "new device" alert.
type NewDeviceFunc func(mac, ip string)

// DeviceTracker turns observed packets into LAN device inventory updates. It
// implements flow.Observer, so it sees every packet, but it debounces writes:
// a device is flushed to the store at most once per interval, keeping the
// database quiet under heavy traffic.
type DeviceTracker struct {
	classifier *flow.Classifier
	store      DeviceStore
	onNew      NewDeviceFunc
	flush      time.Duration

	mu      sync.Mutex
	pending map[string]sighting // keyed by MAC
}

type sighting struct {
	ip string
}

// NewDeviceTracker creates a tracker. onNew may be nil.
func NewDeviceTracker(c *flow.Classifier, store DeviceStore, onNew NewDeviceFunc, flush time.Duration) *DeviceTracker {
	if flush <= 0 {
		flush = 10 * time.Second
	}
	return &DeviceTracker{
		classifier: c,
		store:      store,
		onNew:      onNew,
		flush:      flush,
		pending:    make(map[string]sighting),
	}
}

// Observe implements flow.Observer. It records the local (internal) endpoint's
// MAC/IP pair; routed WAN peers have no meaningful local MAC and are ignored.
func (d *DeviceTracker) Observe(p flow.Packet) {
	// The internal side of the packet is the device we want to inventory.
	if p.SrcMAC != "" && d.classifier.Internal(p.SrcIP) {
		d.note(p.SrcMAC, p.SrcIP.String())
	}
	if p.DstMAC != "" && d.classifier.Internal(p.DstIP) {
		d.note(p.DstMAC, p.DstIP.String())
	}
}

func (d *DeviceTracker) note(mac, ip string) {
	d.mu.Lock()
	d.pending[mac] = sighting{ip: ip}
	d.mu.Unlock()
}

// Flush writes pending sightings to the store and fires onNew for devices seen
// for the first time.
func (d *DeviceTracker) Flush(ctx context.Context) error {
	d.mu.Lock()
	if len(d.pending) == 0 {
		d.mu.Unlock()
		return nil
	}
	batch := d.pending
	d.pending = make(map[string]sighting)
	d.mu.Unlock()

	for mac, s := range batch {
		isNew, err := d.store.UpsertDevice(ctx, mac, s.ip, "", "")
		if err != nil {
			return err
		}
		if isNew && d.onNew != nil {
			d.onNew(mac, s.ip)
		}
	}
	return nil
}

// Run flushes on the configured interval until ctx is cancelled.
func (d *DeviceTracker) Run(ctx context.Context) error {
	t := time.NewTicker(d.flush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return d.Flush(context.WithoutCancel(ctx))
		case <-t.C:
			if err := d.Flush(ctx); err != nil {
				return err
			}
		}
	}
}
