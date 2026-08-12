package capture

import (
	"context"
	"math/rand"
	"net/netip"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// DemoSource synthesizes a plausible stream of home-network traffic so the
// dashboard and detectors can be explored without any privileges or real
// packets. It periodically injects a port scan and a rate burst so the alert
// and firewall views have something to show.
type DemoSource struct {
	rng   *rand.Rand
	now   func() time.Time
	step  time.Duration
	ticks uint64

	devices []demoDevice
	dests   []demoDest
}

type demoDevice struct {
	ip   netip.Addr
	mac  string
	name string
}

type demoDest struct {
	ip   netip.Addr
	name string
	port uint16
}

// DemoOptions configures the generator. The zero value is usable.
type DemoOptions struct {
	// Seed makes the synthetic stream reproducible (defaults to a fixed seed
	// so demo screenshots and tests are stable).
	Seed int64
	// Step is the interval between emission batches (defaults to 250ms).
	Step time.Duration
	// Now overrides the clock (defaults to time.Now).
	Now func() time.Time
}

// NewDemoSource builds a demo generator.
func NewDemoSource(opts DemoOptions) *DemoSource {
	if opts.Step <= 0 {
		opts.Step = 250 * time.Millisecond
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	d := &DemoSource{
		rng:  rand.New(rand.NewSource(opts.Seed)),
		now:  opts.Now,
		step: opts.Step,
	}
	d.devices = []demoDevice{
		{netip.MustParseAddr("192.168.1.20"), "de:ad:be:ef:00:20", "living-room-tv"},
		{netip.MustParseAddr("192.168.1.21"), "de:ad:be:ef:00:21", "julians-macbook"},
		{netip.MustParseAddr("192.168.1.22"), "de:ad:be:ef:00:22", "pixel-phone"},
		{netip.MustParseAddr("192.168.1.23"), "de:ad:be:ef:00:23", "home-assistant"},
		{netip.MustParseAddr("192.168.1.24"), "de:ad:be:ef:00:24", "work-laptop"},
	}
	d.dests = []demoDest{
		{netip.MustParseAddr("140.82.121.3"), "github.com", 443},
		{netip.MustParseAddr("151.101.1.140"), "reddit.com", 443},
		{netip.MustParseAddr("142.250.185.78"), "youtube.com", 443},
		{netip.MustParseAddr("104.16.85.20"), "cloudflare.com", 443},
		{netip.MustParseAddr("9.9.9.9"), "dns.quad9.net", 53},
		{netip.MustParseAddr("17.253.144.10"), "apple.com", 443},
	}
	return d
}

// Name implements Source.
func (d *DemoSource) Name() string { return "demo" }

// Run implements Source: it emits synthetic packets on each step tick.
func (d *DemoSource) Run(ctx context.Context, handle func(flow.Packet)) error {
	t := time.NewTicker(d.step)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			d.Step(handle)
		}
	}
}

// Step emits one batch of packets. It is exported so tests and screenshot
// tooling can drive the generator deterministically without real time.
func (d *DemoSource) Step(handle func(flow.Packet)) {
	now := d.now()
	d.ticks++

	// Baseline: a handful of normal request/reply exchanges.
	batch := 3 + d.rng.Intn(5)
	for i := 0; i < batch; i++ {
		dev := d.devices[d.rng.Intn(len(d.devices))]
		dst := d.dests[d.rng.Intn(len(d.dests))]
		sport := uint16(30000 + d.rng.Intn(20000))
		reqSize := uint64(80 + d.rng.Intn(400))
		respSize := uint64(200 + d.rng.Intn(12000))

		handle(flow.Packet{
			Time: now, SrcIP: dev.ip, DstIP: dst.ip, SrcPort: sport, DstPort: dst.port,
			Proto: protoFor(dst.port), Size: reqSize, SYN: true,
			SrcMAC: dev.mac, DstName: dst.name,
		})
		handle(flow.Packet{
			Time: now, SrcIP: dst.ip, DstIP: dev.ip, SrcPort: dst.port, DstPort: sport,
			Proto: protoFor(dst.port), Size: respSize,
		})
	}

	// Every ~40 steps, a port scan from a random external address.
	if d.ticks%40 == 12 {
		d.emitPortScan(handle, now)
	}
	// Every ~40 steps (offset), a connection-rate burst.
	if d.ticks%40 == 28 {
		d.emitRateBurst(handle, now)
	}
}

func (d *DemoSource) emitPortScan(handle func(flow.Packet), now time.Time) {
	attacker := randomExternal(d.rng)
	target := d.devices[d.rng.Intn(len(d.devices))]
	for port := 1; port <= 30; port++ {
		handle(flow.Packet{
			Time: now, SrcIP: attacker, DstIP: target.ip,
			SrcPort: uint16(40000 + port), DstPort: uint16(port),
			Proto: model.ProtoTCP, Size: 60, SYN: true, DstMAC: target.mac,
		})
	}
}

func (d *DemoSource) emitRateBurst(handle func(flow.Packet), now time.Time) {
	attacker := randomExternal(d.rng)
	target := d.devices[d.rng.Intn(len(d.devices))]
	for i := 0; i < 400; i++ {
		handle(flow.Packet{
			Time: now, SrcIP: attacker, DstIP: target.ip,
			SrcPort: uint16(1024 + d.rng.Intn(60000)), DstPort: 443,
			Proto: model.ProtoTCP, Size: 60, SYN: true, DstMAC: target.mac,
		})
	}
}

func protoFor(port uint16) model.Protocol {
	if port == 53 {
		return model.ProtoUDP
	}
	return model.ProtoTCP
}

func randomExternal(rng *rand.Rand) netip.Addr {
	// Public-looking address that is never inside an RFC 1918 range, so demo
	// scans and bursts classify as WAN→LAN like the real thing.
	for {
		a := netip.AddrFrom4([4]byte{
			byte(1 + rng.Intn(223)),
			byte(rng.Intn(256)),
			byte(rng.Intn(256)),
			byte(1 + rng.Intn(254)),
		})
		o := a.As4()
		private := o[0] == 10 ||
			(o[0] == 172 && o[1] >= 16 && o[1] <= 31) ||
			(o[0] == 192 && o[1] == 168) ||
			o[0] == 127 || o[0] == 169
		if !private {
			return a
		}
	}
}
