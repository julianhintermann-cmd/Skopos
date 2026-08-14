package policy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// scannerFinding is a finding from an address Skopos has never seen before,
// which on a port-forwarded box is a steady trickle all day, for months.
func scannerFinding(i int) detect.Finding {
	addr := netip.AddrFrom4([4]byte{1, byte(i >> 16), byte(i >> 8), byte(i)})
	return detect.Finding{
		Detector: "portscan", Source: addr, Severity: model.SeverityWarning,
		Title: "test", Detail: "detail",
	}
}

type logSpy struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSpy) record(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logSpy) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

// Every finding from an unseen source added a cooldown entry that nothing ever
// removed. internal/detect caps its per-source state at maxTrackedSources for
// exactly this reason and then handed every finding down here, so the leak was
// re-created one layer below the fix.
func TestCooldownMapStopsGrowing(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, _, _ := baseEngine(Config{Enforcement: Observe, Cooldown: 30 * time.Minute},
		func() time.Time { return now })
	spy := &logSpy{}
	e.SetLogger(spy.record)

	// Three times the cap, all inside one cooldown window: the worst case,
	// where ageing can free nothing.
	for i := range 3 * maxCooldownSources {
		e.Raise(scannerFinding(i))
	}

	e.mu.Lock()
	held := len(e.cooldown)
	e.mu.Unlock()
	if held > maxCooldownSources {
		t.Errorf("cooldown map holds %d entries, cap is %d", held, maxCooldownSources)
	}
	stats := e.CooldownStats()
	if stats.Forgotten == 0 {
		t.Error("entries were dropped without being counted")
	}
	if stats.Tracked != held {
		t.Errorf("CooldownStats says %d tracked, map holds %d", stats.Tracked, held)
	}
	// Overrunning the map costs each tracked source one extra notification, so
	// it is said out loud and not left to the counter alone.
	if spy.count() == 0 {
		t.Error("the map was dropped without a word in the log")
	}
}

// Ageing must not touch a source that is still inside its cooldown: dropping
// that entry loses the suppressed count and lets the next finding notify
// early, which is the aggregation the cooldown exists to provide.
func TestCooldownAgeingKeepsSourcesStillInsideTheirWindow(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	e, _, notif, _ := baseEngine(Config{Enforcement: Observe, Cooldown: 30 * time.Minute}, clock)

	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))

	// Half a cooldown on: the entry is still doing its job.
	now = now.Add(15 * time.Minute)
	e.mu.Lock()
	shed := e.ageCooldownLocked(now)
	held := len(e.cooldown)
	e.mu.Unlock()
	if shed.forgotten != 0 || held != 1 {
		t.Fatalf("ageing dropped a live entry: forgot %d, %d left", shed.forgotten, held)
	}

	// And the aggregation it was holding still arrives.
	now = now.Add(20 * time.Minute)
	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	if notif.count() != 2 {
		t.Fatalf("notifications = %d, want 2", notif.count())
	}
}

// Past two cooldowns of silence the entry suppresses nothing, so it goes — and
// whatever it still had to say goes into the counters rather than nowhere.
func TestCooldownAgeingReportsWhatItGivesUp(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	e, _, _, _ := baseEngine(Config{Enforcement: Observe, Cooldown: 30 * time.Minute}, clock)

	// One notification and three occurrences suppressed behind it.
	for range 4 {
		e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	}

	now = now.Add(90 * time.Minute)
	e.mu.Lock()
	shed := e.ageCooldownLocked(now)
	held := len(e.cooldown)
	e.mu.Unlock()

	if shed.forgotten != 1 || held != 0 {
		t.Fatalf("the quiet source was not reclaimed: forgot %d, %d left", shed.forgotten, held)
	}
	if shed.unreported != 3 {
		t.Errorf("unreported occurrences = %d, want 3", shed.unreported)
	}
	if got := e.CooldownStats(); got.Forgotten != 1 || got.Unreported != 3 {
		t.Errorf("CooldownStats = %+v, want 1 forgotten and 3 unreported", got)
	}
}

// Bounding the map must not cost protection: a source whose cooldown entry was
// dropped is still blocked, still alerted on, still counted.
func TestCooldownReclamationKeepsAlertingAndBlocking(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, store, notif, blocker := baseEngine(Config{
		Enforcement: Enforce, Cooldown: 30 * time.Minute, BlockTTL: time.Hour,
	}, func() time.Time { return now })

	for i := range maxCooldownSources + 100 {
		f := scannerFinding(i)
		f.SuggestBlock = true
		e.Raise(f)
	}

	want := maxCooldownSources + 100
	if len(store.alerts) != want {
		t.Errorf("stored alerts = %d, want %d (one per distinct source)", len(store.alerts), want)
	}
	if notif.count() != want {
		t.Errorf("notifications = %d, want %d", notif.count(), want)
	}
	if blocker.count() != want {
		t.Errorf("blocks = %d, want %d", blocker.count(), want)
	}
}
