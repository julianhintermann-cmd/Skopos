package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func TestAddAndListActiveBlocks(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	_, err := s.AddBlock(ctx, model.Block{
		Prefix: netip.MustParsePrefix("203.0.113.5/32"),
		Origin: model.OriginManual, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := s.ActiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Prefix.String() != "203.0.113.5/32" {
		t.Fatalf("active blocks = %+v", active)
	}
	_ = base
}

func TestAddBlockDedupesActivePrefix(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := netip.MustParsePrefix("203.0.113.5/32")

	_, _ = s.AddBlock(ctx, model.Block{Prefix: p, Origin: model.OriginDetector, Reason: "first"})
	_, _ = s.AddBlock(ctx, model.Block{Prefix: p, Origin: model.OriginManual, Reason: "second"})

	active, _ := s.ActiveBlocks(ctx)
	if len(active) != 1 {
		t.Fatalf("expected 1 active block after re-adding same prefix, got %d", len(active))
	}
	if active[0].Reason != "second" || active[0].Origin != model.OriginManual {
		t.Errorf("re-add should update fields, got %+v", active[0])
	}
}

func TestRemoveBlock(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := netip.MustParsePrefix("203.0.113.5/32")

	_, _ = s.AddBlock(ctx, model.Block{Prefix: p, Origin: model.OriginManual})
	removed, err := s.RemoveBlock(ctx, p)
	if err != nil || !removed {
		t.Fatalf("RemoveBlock = %v, %v", removed, err)
	}
	active, _ := s.ActiveBlocks(ctx)
	if len(active) != 0 {
		t.Errorf("expected no active blocks after removal, got %d", len(active))
	}
	// Removing again is a no-op.
	removed, _ = s.RemoveBlock(ctx, p)
	if removed {
		t.Error("second removal should report false")
	}
}

func TestExpireBlocks(t *testing.T) {
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	now := base
	s, err := Open(Options{Path: t.TempDir() + "/db.sqlite", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	past := base.Add(-time.Hour)
	future := base.Add(time.Hour)
	_, _ = s.AddBlock(ctx, model.Block{Prefix: netip.MustParsePrefix("203.0.113.5/32"), Origin: model.OriginDetector, Expires: &past})
	_, _ = s.AddBlock(ctx, model.Block{Prefix: netip.MustParsePrefix("203.0.113.6/32"), Origin: model.OriginDetector, Expires: &future})
	permanent := model.Block{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Origin: model.OriginManual}
	_, _ = s.AddBlock(ctx, permanent)

	expired, err := s.ExpireBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].Prefix.String() != "203.0.113.5/32" {
		t.Fatalf("expired = %+v, want just the past-TTL block", expired)
	}
	active, _ := s.ActiveBlocks(ctx)
	if len(active) != 2 {
		t.Errorf("active after expiry = %d, want 2 (future + permanent)", len(active))
	}
}

func TestAuditRoundTrip(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()

	if err := s.Audit(ctx, model.AuditEntry{Actor: "admin", Action: "block", Target: "203.0.113.5", Detail: "manual"}); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "block" {
		t.Fatalf("audit entries = %+v", entries)
	}
}
