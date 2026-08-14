package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// seedAudit writes entries at one-minute intervals ending at base, so a window
// filter has something to cut.
func seedAudit(t *testing.T, s *Store, entries ...model.AuditEntry) {
	t.Helper()
	ctx := context.Background()
	for _, e := range entries {
		if err := s.Audit(ctx, e); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}
}

func targets(entries []model.AuditEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Target)
	}
	return out
}

// The question the whole filter exists for: an operator types an address and
// wants every entry about it. A block records the prefix and a login records
// the bare address, so an exact match would answer "nothing" while the log
// holds the entry — the worst reply an audit log can give.
func TestListAuditPageFiltersByTargetPrefix(t *testing.T) {
	s, base := testStore(t)
	seedAudit(t, s,
		model.AuditEntry{Time: base, Actor: "julian", Action: "block", Target: "203.0.113.5/32", Detail: "kept knocking"},
		model.AuditEntry{Time: base, Actor: "julian", Action: "login", Target: "203.0.113.5", Detail: ""},
		model.AuditEntry{Time: base, Actor: "system", Action: "unblock", Target: "203.0.113.50/32", Detail: "ttl expired"},
		model.AuditEntry{Time: base, Actor: "system", Action: "block", Target: "198.51.100.7/32", Detail: "feeds"},
	)

	page, err := s.ListAuditPage(context.Background(), AuditFilter{Target: "203.0.113.5"})
	if err != nil {
		t.Fatalf("ListAuditPage: %v", err)
	}
	// 203.0.113.50/32 shares the leading text and is a different address, but
	// prefix matching cannot tell them apart — the filter narrows, it does not
	// resolve addresses, and saying so is better than pretending otherwise.
	if got := len(page.Entries); got != 3 {
		t.Errorf("target filter returned %d entries (%v), want the 3 that start with the address",
			got, targets(page.Entries))
	}
	for _, e := range page.Entries {
		if e.Target == "198.51.100.7/32" {
			t.Error("the filter returned an unrelated address")
		}
	}
}

// LIKE's own wildcards must not leak out of a target the operator typed.
func TestListAuditPageEscapesWildcardsInTarget(t *testing.T) {
	s, base := testStore(t)
	seedAudit(t, s,
		model.AuditEntry{Time: base, Actor: "a", Action: "login", Target: "host_1"},
		model.AuditEntry{Time: base, Actor: "a", Action: "login", Target: "hostX1"},
		model.AuditEntry{Time: base, Actor: "a", Action: "login", Target: "100%pure"},
		model.AuditEntry{Time: base, Actor: "a", Action: "login", Target: "100pure"},
	)

	for _, tc := range []struct{ target, want string }{
		{"host_", "host_1"},
		{"100%", "100%pure"},
	} {
		page, err := s.ListAuditPage(context.Background(), AuditFilter{Target: tc.target})
		if err != nil {
			t.Fatalf("ListAuditPage: %v", err)
		}
		if len(page.Entries) != 1 || page.Entries[0].Target != tc.want {
			t.Errorf("target %q matched %v, want only %q", tc.target, targets(page.Entries), tc.want)
		}
	}
}

func TestListAuditPageFiltersByActorActionAndWindow(t *testing.T) {
	s, base := testStore(t)
	seedAudit(t, s,
		model.AuditEntry{Time: base.Add(-3 * time.Hour), Actor: "julian", Action: "block", Target: "a"},
		model.AuditEntry{Time: base.Add(-2 * time.Hour), Actor: "system", Action: "block", Target: "b"},
		model.AuditEntry{Time: base.Add(-1 * time.Hour), Actor: "julian", Action: "unblock", Target: "c"},
		model.AuditEntry{Time: base, Actor: "julian", Action: "block", Target: "d"},
	)
	ctx := context.Background()

	cases := []struct {
		name   string
		filter AuditFilter
		want   []string
	}{
		{"by actor", AuditFilter{Actor: "julian"}, []string{"d", "c", "a"}},
		{"by action", AuditFilter{Action: "block"}, []string{"d", "b", "a"}},
		{"by both", AuditFilter{Actor: "julian", Action: "block"}, []string{"d", "a"}},
		{
			"since is inclusive, until exclusive",
			AuditFilter{Since: base.Add(-2 * time.Hour), Until: base},
			[]string{"c", "b"},
		},
		{"an actor nobody wrote returns nothing", AuditFilter{Actor: "nobody"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.ListAuditPage(ctx, tc.filter)
			if err != nil {
				t.Fatalf("ListAuditPage: %v", err)
			}
			got := targets(page.Entries)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// Paging has to return every entry exactly once. The store's clock is fixed in
// these tests, so every entry here shares a millisecond — which is the case a
// cursor on time alone gets wrong, and it is not contrived: a self-heal
// reapplies a ruleset and audits it inside the same millisecond.
func TestListAuditPageWalksTheWholeLogWithoutRepeatingOrSkipping(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	const total = 25
	for i := range total {
		if err := s.Audit(ctx, model.AuditEntry{
			Time: base, Actor: "system", Action: "block", Target: fmt.Sprintf("t%02d", i),
		}); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}

	seen := map[string]int{}
	var cursor AuditCursor
	var pages int
	for {
		page, err := s.ListAuditPage(ctx, AuditFilter{Limit: 7, Before: cursor})
		if err != nil {
			t.Fatalf("ListAuditPage: %v", err)
		}
		for _, e := range page.Entries {
			seen[e.Target]++
		}
		pages++
		if pages > total {
			t.Fatal("paging did not terminate")
		}
		if page.Next.Zero() {
			// The last page is short, and its emptiness marker is what says so.
			if len(page.Entries) != total%7 {
				t.Errorf("the final page held %d entries, want %d", len(page.Entries), total%7)
			}
			break
		}
		if len(page.Entries) != 7 {
			t.Fatalf("a page offering a continuation held %d entries, want 7", len(page.Entries))
		}
		cursor = page.Next
	}

	if len(seen) != total {
		t.Errorf("paging returned %d distinct entries, want %d", len(seen), total)
	}
	for target, n := range seen {
		if n != 1 {
			t.Errorf("%s came back %d times", target, n)
		}
	}
}

// A page that exactly empties the log must not offer a continuation: a client
// following it would be shown an empty page and could not tell that from a log
// that had been cleared.
func TestListAuditPageEndsWithoutAnEmptyNextPage(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()
	for i := range 4 {
		seedAudit(t, s, model.AuditEntry{
			Time: base, Actor: "system", Action: "block", Target: fmt.Sprintf("t%d", i),
		})
	}

	page, err := s.ListAuditPage(ctx, AuditFilter{Limit: 4})
	if err != nil {
		t.Fatalf("ListAuditPage: %v", err)
	}
	if len(page.Entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(page.Entries))
	}
	if !page.Next.Zero() {
		t.Errorf("a page holding the whole log offered a continuation (%s)", page.Next)
	}
}

func TestAuditCursorRoundTrips(t *testing.T) {
	c := AuditCursor{TimeMs: 1786000000000, ID: 4321}
	back, err := ParseAuditCursor(c.String())
	if err != nil {
		t.Fatalf("ParseAuditCursor(%q): %v", c, err)
	}
	if back != c {
		t.Errorf("round trip gave %+v, want %+v", back, c)
	}
	if (AuditCursor{}).String() != "" {
		t.Error("the zero cursor must render as the empty string")
	}
}

// An unparseable cursor is an error, not the newest entries: silently
// restarting at the top would show an operator the same page again and let
// them conclude the entries they were paging towards do not exist.
func TestParseAuditCursorRefusesGarbage(t *testing.T) {
	for _, in := range []string{"nonsense", "123", "abc.4", "12.xyz", ".", "12."} {
		if _, err := ParseAuditCursor(in); err == nil {
			t.Errorf("ParseAuditCursor(%q) was accepted", in)
		}
	}
	if c, err := ParseAuditCursor(""); err != nil || !c.Zero() {
		t.Errorf(`ParseAuditCursor("") = %+v, %v; want the zero cursor and no error`, c, err)
	}
}
