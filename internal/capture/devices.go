package capture

import (
	"context"
	"net/netip"
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
	hostname   func(netip.Addr) string
	onFlush    func(error)
	flush      time.Duration

	mu      sync.Mutex
	pending map[string]sighting // keyed by MAC
}

// sighting is what one flush interval learned about a device: at most one
// address per family. A dual-stack machine is one device, not two, and its
// IPv4 address is the one an operator recognises — so both are kept and
// neither overwrites the other.
type sighting struct {
	v4, v6 netip.Addr
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

// SetHostnameLookup supplies the passive-DNS resolver, so a device that
// announces itself over mDNS ("printer.local") is inventoried under that name
// instead of a bare MAC address. Optional: without it the hostname column
// stays empty and the operator's own label is the only name.
func (d *DeviceTracker) SetHostnameLookup(f func(netip.Addr) string) { d.hostname = f }

// SetFlushReporter installs a callback that receives the outcome of every
// flush: the error when one fails, nil on the first success afterwards. It
// exists because this loop used to end permanently on the first error, taking
// device inventory, new-device alerts and presence tracking with it, and doing
// so without a single line anywhere. Optional.
func (d *DeviceTracker) SetFlushReporter(f func(error)) { d.onFlush = f }

// Observe implements flow.Observer. It records the local (internal) endpoint's
// MAC/IP pair; routed WAN peers have no meaningful local MAC and are ignored.
func (d *DeviceTracker) Observe(p flow.Packet) {
	// The internal side of the packet is the device we want to inventory.
	if p.SrcMAC != "" && d.inventoryable(p.SrcIP) {
		d.note(p.SrcMAC, p.SrcIP)
	}
	if p.DstMAC != "" && d.inventoryable(p.DstIP) {
		d.note(p.DstMAC, p.DstIP)
	}
}

// inventoryable reports whether an address can stand for a device. Beyond
// being internal it has to name a single machine: the unspecified address,
// loopback, multicast groups and the all-ones broadcast address never do.
func (d *DeviceTracker) inventoryable(a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return false
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return d.classifier.Internal(a)
}

func (d *DeviceTracker) note(mac string, addr netip.Addr) {
	addr = addr.Unmap()
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.pending[mac]
	if addr.Is4() {
		s.v4 = addr
	} else if better(s.v6, addr) {
		s.v6 = addr
	}
	d.pending[mac] = s
}

// better reports whether cand is a more useful IPv6 address to remember than
// cur. Every interface has a fe80:: link-local address and most traffic on a
// LAN uses it, but "fe80::8f5:45d3:3bc2:b3ea" tells an operator nothing — a
// routable address wins whenever the device has one.
func better(cur, cand netip.Addr) bool {
	if !cur.IsValid() {
		return true
	}
	return cur.IsLinkLocalUnicast() && !cand.IsLinkLocalUnicast()
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
		// IPv4 first: when a device is new, that is the address worth
		// naming it by in the alert.
		fresh, err := d.record(ctx, mac, s.v4)
		if err != nil {
			return err
		}
		if again, err := d.record(ctx, mac, s.v6); err != nil {
			return err
		} else if again && !s.v4.IsValid() {
			fresh = true
		}
		if fresh && d.onNew != nil {
			d.onNew(mac, firstValid(s.v4, s.v6).String())
		}
	}
	return nil
}

// record upserts one address of one device. The store may decline to create a
// new entry — it refuses an address that too many distinct MACs have already
// claimed — which reports as "not new" rather than as an error: it is a
// statement about the traffic, not a failure to write.
func (d *DeviceTracker) record(ctx context.Context, mac string, addr netip.Addr) (bool, error) {
	if !addr.IsValid() {
		return false, nil
	}
	host := ""
	if d.hostname != nil {
		host = d.hostname(addr)
	}
	return d.store.UpsertDevice(ctx, mac, addr.String(), host, "")
}

func firstValid(addrs ...netip.Addr) netip.Addr {
	for _, a := range addrs {
		if a.IsValid() {
			return a
		}
	}
	return netip.Addr{}
}

// Run flushes on the configured interval until ctx is cancelled.
//
// A failed flush used to return, which ended the goroutine for good — and the
// caller discarded the error, so one transient write failure silently stopped
// device inventory, new-device alerts and presence tracking for the lifetime
// of the process. Worse, frozen last-seen timestamps then made the presence
// watcher announce that devices had left the network when they had not. Keep
// ticking and report instead, the same way the flow aggregator does.
func (d *DeviceTracker) Run(ctx context.Context) error {
	t := time.NewTicker(d.flush)
	defer t.Stop()
	var failing bool
	for {
		select {
		case <-ctx.Done():
			return d.Flush(context.WithoutCancel(ctx))
		case <-t.C:
			err := d.Flush(ctx)
			switch {
			case err != nil:
				failing = true
			case failing:
				failing = false
			default:
				continue
			}
			if d.onFlush != nil {
				d.onFlush(err)
			}
		}
	}
}
