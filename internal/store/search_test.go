package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// A subnet search used to apply its row limit in SQL and only then test the
// CIDR in Go, so the limit was spent on flows that did not match. On a network
// with ordinary traffic the newest rows are rarely the ones being searched
// for, and the screen answered "Nothing matched" during an investigation while
// the matches sat just past the cut. This is the regression test for that.
func TestSearchFlowsAppliesCIDRBeforeTheLimit(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	// One flow from the subnet under investigation, then a wall of newer,
	// unrelated traffic — the shape of a real network.
	batch := []model.Flow{mkFlow(base, "10.7.7.7", "9.9.9.9", 443, 1000)}
	for i := 1; i <= 600; i++ {
		batch = append(batch, mkFlow(
			base.Add(time.Duration(i)*time.Second),
			fmt.Sprintf("192.168.1.%d", i%200+10), "1.1.1.1", 53, 200))
	}
	if err := s.WriteFlows(batch); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	got, truncated, err := s.SearchFlows(ctx, SearchFilter{
		From: base.Add(-time.Minute), To: base.Add(time.Hour),
		Address: "10.0.0.0/8", Limit: 300,
	})
	if err != nil {
		t.Fatalf("SearchFlows: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the flow inside 10.0.0.0/8 was not found: got %d matches", len(got))
	}
	if got[0].SrcIP.String() != "10.7.7.7" {
		t.Errorf("wrong flow returned: %v", got[0].SrcIP)
	}
	if truncated {
		t.Error("a complete answer must not be reported as truncated")
	}
}

// And the honest half: when more matches exist than fit, say so rather than
// let the caller present a capped page as the whole answer.
func TestSearchFlowsReportsTruncation(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	var batch []model.Flow
	for i := range 50 {
		batch = append(batch, mkFlow(
			base.Add(time.Duration(i)*time.Second),
			fmt.Sprintf("10.0.0.%d", i+1), "9.9.9.9", 443, 100))
	}
	if err := s.WriteFlows(batch); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	got, truncated, err := s.SearchFlows(ctx, SearchFilter{
		From: base.Add(-time.Minute), To: base.Add(time.Hour),
		Address: "10.0.0.0/8", Limit: 10,
	})
	if err != nil {
		t.Fatalf("SearchFlows: %v", err)
	}
	if len(got) != 10 {
		t.Fatalf("expected the requested 10 rows, got %d", len(got))
	}
	if !truncated {
		t.Error("40 further matches exist; the result must be reported as truncated")
	}
}

// An exact address still filters in SQL, so its limit is honest as it stands.
func TestSearchFlowsExactAddressUnaffected(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()
	if err := s.WriteFlows([]model.Flow{
		mkFlow(base, "10.7.7.7", "9.9.9.9", 443, 1000),
		mkFlow(base.Add(time.Second), "192.168.1.10", "1.1.1.1", 53, 200),
	}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}
	got, truncated, err := s.SearchFlows(ctx, SearchFilter{
		From: base.Add(-time.Minute), To: base.Add(time.Hour),
		Address: "10.7.7.7", Limit: 300,
	})
	if err != nil {
		t.Fatalf("SearchFlows: %v", err)
	}
	if len(got) != 1 || truncated {
		t.Errorf("got %d flows truncated=%v, want 1 and false", len(got), truncated)
	}
}

// One URL parameter used to turn a sub-millisecond request into a 45-second
// one — measured — by asking for minute buckets across ninety days. Every
// query shares one database connection, so that also stalls the flow writer
// and every other page, and the port it arrives on has no authentication.
func TestClampResolutionRefusesFinerThanTheSpanWarrants(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		span      time.Duration
		requested Resolution
		want      Resolution
	}{
		{90 * day, Res1m, Res1h}, // the attack
		{365 * day, Res1m, Res1d},
		{365 * day, Res1h, Res1d},
		{time.Hour, Res1m, Res1m},  // a fine resolution over a narrow span is fine
		{time.Hour, Res1d, Res1d},  // coarser than needed stays allowed
		{90 * day, Res1d, Res1d},   // ditto
		{2 * time.Hour, "", Res1m}, // an unknown value is treated as the finest
	}
	for _, c := range cases {
		if got := ClampResolution(c.requested, c.span); got != c.want {
			t.Errorf("ClampResolution(%q, %s) = %q, want %q", c.requested, c.span, got, c.want)
		}
	}
}
