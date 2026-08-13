package policy

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/detect"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

type memAlertStore struct {
	mu     sync.Mutex
	alerts []model.Alert
	nextID int64
}

func (m *memAlertStore) InsertAlert(_ context.Context, a model.Alert) (model.Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	a.ID = m.nextID
	m.alerts = append(m.alerts, a)
	return a, nil
}

type recNotifier struct {
	mu     sync.Mutex
	alerts []model.Alert
}

func (r *recNotifier) Notify(_ context.Context, a model.Alert) {
	r.mu.Lock()
	r.alerts = append(r.alerts, a)
	r.mu.Unlock()
}

func (r *recNotifier) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.alerts)
}

type recBlocker struct {
	mu      sync.Mutex
	blocked []netip.Prefix
}

func (b *recBlocker) Block(_ context.Context, p netip.Prefix, _ string, _ time.Duration) error {
	b.mu.Lock()
	b.blocked = append(b.blocked, p)
	b.mu.Unlock()
	return nil
}

func (b *recBlocker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.blocked)
}

func finding(det, src string, sev model.Severity, block bool) detect.Finding {
	return detect.Finding{
		Detector: det, Source: netip.MustParseAddr(src), Severity: sev,
		Title: "test", Detail: "detail", SuggestBlock: block,
	}
}

func baseEngine(cfg Config, clock func() time.Time) (*Engine, *memAlertStore, *recNotifier, *recBlocker) {
	store := &memAlertStore{}
	notif := &recNotifier{}
	blocker := &recBlocker{}
	e := New(cfg, store, notif, blocker, clock)
	return e, store, notif, blocker
}

func TestCooldownAggregates(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	e, store, notif, _ := baseEngine(Config{
		Enforcement: Observe, Cooldown: 30 * time.Minute,
	}, clock)

	// Five findings for the same (detector, source) within the cooldown.
	for i := 0; i < 5; i++ {
		e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	}
	// Only the first notifies.
	if notif.count() != 1 {
		t.Errorf("notifications = %d, want 1 within cooldown", notif.count())
	}
	if len(store.alerts) != 1 {
		t.Errorf("stored alerts = %d, want 1", len(store.alerts))
	}

	// After the cooldown passes, the next finding notifies and reports the
	// suppressed count.
	now = now.Add(31 * time.Minute)
	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	if notif.count() != 2 {
		t.Fatalf("notifications = %d, want 2 after cooldown", notif.count())
	}
	last := store.alerts[len(store.alerts)-1]
	if last.Count != 5 {
		t.Errorf("aggregated count = %d, want 5 (1 new + 4 suppressed)", last.Count)
	}
}

func TestCooldownIsPerSource(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, notif, _ := baseEngine(Config{Enforcement: Observe, Cooldown: 30 * time.Minute},
		func() time.Time { return now })

	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	e.Raise(finding("portscan", "203.0.113.6", model.SeverityWarning, false))
	if notif.count() != 2 {
		t.Errorf("distinct sources should each notify, got %d", notif.count())
	}
}

func TestObserveModeDoesNotBlock(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, _, blocker := baseEngine(Config{
		Enforcement: Observe, Cooldown: time.Minute, BlockTTL: time.Hour,
	}, func() time.Time { return now })

	e.Raise(finding("feeds", "203.0.113.5", model.SeverityCritical, true))
	if blocker.count() != 0 {
		t.Errorf("observe mode must not block, got %d blocks", blocker.count())
	}
}

func TestEnforceModeBlocks(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, _, blocker := baseEngine(Config{
		Enforcement: Enforce, Cooldown: time.Minute, BlockTTL: time.Hour,
	}, func() time.Time { return now })

	e.Raise(finding("feeds", "203.0.113.5", model.SeverityCritical, true))
	if blocker.count() != 1 {
		t.Fatalf("enforce mode must block, got %d", blocker.count())
	}
	if blocker.blocked[0].Addr().String() != "203.0.113.5" {
		t.Errorf("blocked wrong address: %s", blocker.blocked[0])
	}
}

func TestAllowlistAndGatewayNeverBlocked(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, _, blocker := baseEngine(Config{
		Enforcement: Enforce, Cooldown: time.Minute, BlockTTL: time.Hour,
		Allowlist: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
		Gateway:   netip.MustParseAddr("192.168.1.1"),
	}, func() time.Time { return now })

	// Allowlisted source: no block.
	e.Raise(finding("rate", "192.168.1.50", model.SeverityCritical, true))
	// Gateway: no block.
	e.Raise(finding("rate", "192.168.1.1", model.SeverityCritical, true))
	if blocker.count() != 0 {
		t.Errorf("allowlisted/gateway must never be blocked, got %d", blocker.count())
	}

	// A non-allowlisted external source still gets blocked.
	e.Raise(finding("rate", "203.0.113.9", model.SeverityCritical, true))
	if blocker.count() != 1 {
		t.Errorf("external source should be blocked, got %d", blocker.count())
	}
}

func TestBlockingSurvivesNotificationCooldown(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	e, _, notif, blocker := baseEngine(Config{
		Enforcement: Enforce, Cooldown: 30 * time.Minute, BlockTTL: time.Hour,
	}, func() time.Time { return now })

	// Two findings for the same source: the second is within the notification
	// cooldown, but blocking must still be evaluated both times (protection is
	// not throttled).
	e.Raise(finding("feeds", "203.0.113.5", model.SeverityCritical, true))
	e.Raise(finding("feeds", "203.0.113.5", model.SeverityCritical, true))
	if notif.count() != 1 {
		t.Errorf("notifications = %d, want 1 (cooldown)", notif.count())
	}
	if blocker.count() != 2 {
		t.Errorf("blocks = %d, want 2 (blocking is not throttled by notify cooldown)", blocker.count())
	}
}

func TestQuietHoursSuppressLowSeverity(t *testing.T) {
	// 02:00 local, inside a 23:00–07:00 quiet window.
	night := time.Date(2026, 8, 12, 2, 0, 0, 0, time.UTC)
	e, _, notif, _ := baseEngine(Config{
		Enforcement: Observe, Cooldown: time.Minute,
		QuietHours: QuietHours{
			Enabled:     true,
			From:        time.Date(0, 1, 1, 23, 0, 0, 0, time.UTC),
			To:          time.Date(0, 1, 1, 7, 0, 0, 0, time.UTC),
			MinSeverity: model.SeverityCritical,
		},
	}, func() time.Time { return night })

	// Warning at night: recorded but not notified.
	e.Raise(finding("portscan", "203.0.113.5", model.SeverityWarning, false))
	if notif.count() != 0 {
		t.Errorf("warning during quiet hours should not notify, got %d", notif.count())
	}
	// Critical at night: notified.
	e.Raise(finding("feeds", "203.0.113.6", model.SeverityCritical, false))
	if notif.count() != 1 {
		t.Errorf("critical during quiet hours should notify, got %d", notif.count())
	}
}

func TestInWindowCrossesMidnight(t *testing.T) {
	from := time.Date(0, 1, 1, 23, 0, 0, 0, time.UTC)
	to := time.Date(0, 1, 1, 7, 0, 0, 0, time.UTC)
	in := func(h, m int) bool {
		return inWindow(time.Date(2026, 8, 12, h, m, 0, 0, time.UTC), from, to)
	}
	if !in(23, 30) || !in(2, 0) || !in(6, 59) {
		t.Error("times inside the midnight-crossing window should match")
	}
	if in(7, 0) || in(12, 0) || in(22, 59) {
		t.Error("times outside the window should not match")
	}
}

func TestAlreadyBlockedSourcesAreSilenced(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	blockedSet := map[string]bool{"203.0.113.5": true}
	e, store, notif, blocker := baseEngine(Config{
		Enforcement: Enforce, Cooldown: time.Minute, BlockTTL: time.Hour,
		AlreadyBlocked: func(a netip.Addr) bool { return blockedSet[a.String()] },
	}, clock)

	// A source the kernel already drops: no alert, no notification, no
	// redundant re-block — its traffic shows up in the block counters instead.
	e.Raise(finding("feeds", "203.0.113.5", model.SeverityCritical, true))
	if len(store.alerts) != 0 || notif.count() != 0 || blocker.count() != 0 {
		t.Errorf("already-blocked source raised alerts=%d notifs=%d blocks=%d, want 0/0/0",
			len(store.alerts), notif.count(), blocker.count())
	}

	// A fresh source still goes through the full path.
	e.Raise(finding("feeds", "203.0.113.9", model.SeverityCritical, true))
	if len(store.alerts) != 1 || notif.count() != 1 || blocker.count() != 1 {
		t.Errorf("fresh source raised alerts=%d notifs=%d blocks=%d, want 1/1/1",
			len(store.alerts), notif.count(), blocker.count())
	}
}
