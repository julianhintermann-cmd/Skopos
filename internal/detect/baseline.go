package detect

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/flow"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// BaselineConfig configures the behavioural detector.
type BaselineConfig struct {
	// Bucket is the accounting interval; one value per device per bucket.
	Bucket time.Duration
	// History is how many completed buckets form the baseline. A day of
	// hourly buckets is enough to know a device's rhythm without needing
	// weeks before it says anything.
	History int
	// MinBuckets is how many buckets must be observed before the detector
	// judges anything. Below it, everything looks anomalous.
	MinBuckets int
	// Factor is how many times the typical volume counts as an anomaly.
	Factor float64
	// MinBytes is a floor: a device that normally sends nothing must not
	// alert because it sent one kilobyte.
	MinBytes uint64
	// Severity of the finding.
	Severity model.Severity
	// IsInternal identifies the LAN devices this detector watches.
	IsInternal func(netip.Addr) bool
}

// Baseline learns what each device's traffic normally looks like and reports
// departures from it. Threshold detectors catch what someone else decided is
// too much; this catches what is unusual *for this device* — the printer that
// suddenly uploads a gigabyte, the camera that starts talking at 3am.
//
// It deliberately never suggests a block: "unusual" is not "malicious", and a
// device misbehaving for benign reasons should not lose its network.
type Baseline struct {
	cfg   BaselineConfig
	sink  Sink
	clock Clock

	mu      sync.Mutex
	devices map[netip.Addr]*deviceHistory
}

type deviceHistory struct {
	bucketStart time.Time
	current     uint64
	history     []uint64 // completed buckets, oldest first
	firedAt     time.Time
}

// NewBaseline creates the detector with sane defaults for missing fields.
func NewBaseline(cfg BaselineConfig, sink Sink, clock Clock) *Baseline {
	if clock == nil {
		clock = time.Now
	}
	if cfg.Bucket <= 0 {
		cfg.Bucket = time.Hour
	}
	if cfg.History <= 0 {
		cfg.History = 24
	}
	if cfg.MinBuckets <= 0 {
		cfg.MinBuckets = 6
	}
	if cfg.Factor <= 1 {
		cfg.Factor = 8
	}
	if cfg.MinBytes == 0 {
		cfg.MinBytes = 50 << 20 // 50 MiB
	}
	if cfg.Severity == "" {
		cfg.Severity = model.SeverityWarning
	}
	if cfg.IsInternal == nil {
		cfg.IsInternal = func(netip.Addr) bool { return false }
	}
	return &Baseline{cfg: cfg, sink: sink, clock: clock, devices: map[netip.Addr]*deviceHistory{}}
}

// Observe implements flow.Observer, accumulating each LAN device's outbound
// volume. Outbound only: what a device *sends* is the interesting signal —
// inbound is largely whatever the internet decided to throw at it.
func (b *Baseline) Observe(p flow.Packet) {
	if !b.cfg.IsInternal(p.SrcIP) || b.cfg.IsInternal(p.DstIP) {
		return
	}
	now := p.Time
	if now.IsZero() {
		now = b.clock()
	}
	bucket := now.Truncate(b.cfg.Bucket)

	b.mu.Lock()
	d := b.devices[p.SrcIP]
	if d == nil {
		// Bound the map: a scan spoofing many source addresses must not
		// grow it without limit. LAN devices are few; the cap is generous.
		if len(b.devices) > 1024 {
			b.mu.Unlock()
			return
		}
		d = &deviceHistory{bucketStart: bucket}
		b.devices[p.SrcIP] = d
	}

	if bucket.After(d.bucketStart) {
		// The bucket closed: judge it, then start the next one.
		finished := d.current
		d.history = append(d.history, finished)
		if len(d.history) > b.cfg.History {
			d.history = d.history[len(d.history)-b.cfg.History:]
		}
		d.current = 0
		d.bucketStart = bucket

		if f, ok := b.judge(p.SrcIP, d, finished, now); ok {
			b.mu.Unlock()
			b.sink.Raise(f)
			return
		}
	}
	d.current += p.Size
	b.mu.Unlock()
}

// judge compares a completed bucket against the device's own history.
// Callers hold b.mu.
func (b *Baseline) judge(addr netip.Addr, d *deviceHistory, value uint64, now time.Time) (Finding, bool) {
	// The just-finished bucket is already in history; compare against the
	// ones before it.
	prior := d.history[:len(d.history)-1]
	if len(prior) < b.cfg.MinBuckets {
		return Finding{}, false
	}
	if value < b.cfg.MinBytes {
		return Finding{}, false
	}
	// One finding per device per history window, so a device that stays
	// busy does not alert every hour.
	if !d.firedAt.IsZero() && now.Sub(d.firedAt) < time.Duration(b.cfg.History)*b.cfg.Bucket {
		return Finding{}, false
	}
	typical := median(prior)
	if typical == 0 {
		// A device that normally sends nothing: MinBytes already decided
		// this is worth mentioning.
		typical = 1
	}
	ratio := float64(value) / float64(typical)
	if ratio < b.cfg.Factor {
		return Finding{}, false
	}
	d.firedAt = now

	return Finding{
		Detector: "baseline",
		Source:   addr,
		Severity: b.cfg.Severity,
		Title:    fmt.Sprintf("Unusual traffic from %s", addr),
		Detail: fmt.Sprintf("sent %s in the last %s — %.0f× its usual %s",
			humanBytes(value), b.cfg.Bucket, ratio, humanBytes(typical)),
		// Unusual is not malicious: this detector informs, it never blocks.
		SuggestBlock: false,
	}, true
}

// median of a copy, so the caller's slice keeps its chronological order.
func median(v []uint64) uint64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]uint64(nil), v...)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// humanBytes renders a byte count the way the dashboard does.
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTP"[exp])
}

// Devices reports how many devices have a baseline, for the system view.
func (b *Baseline) Devices() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.devices)
}
