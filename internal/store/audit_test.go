package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// The same missing ceiling as ListAlerts, over a table that is also unretained
// and also read newest-first with no window.
func TestListAuditClampsACallerSuppliedLimit(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	const stored = defaultAuditRows + 50
	for i := range stored {
		if err := s.Audit(ctx, model.AuditEntry{
			Time: base, Actor: "test", Action: "block",
			Target: fmt.Sprintf("203.0.113.%d", i%256), Detail: "detail",
		}); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}

	cases := []struct {
		name  string
		limit int
		want  int
	}{
		{"unset falls back to the default", 0, defaultAuditRows},
		{"a sane limit is honoured", 50, 50},
		{"at the ceiling everything stored comes back", auditRowCap, stored},
		{"above the ceiling falls back to the default", 1 << 30, defaultAuditRows},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListAudit(ctx, tc.limit)
			if err != nil {
				t.Fatalf("ListAudit: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("limit %d returned %d rows, want %d", tc.limit, len(got), tc.want)
			}
		})
	}
}
