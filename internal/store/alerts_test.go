package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// Alerts and audit were the two listings whose caller-supplied limit had no
// ceiling. Both tables are unretained and both are read newest-first with no
// window, so `?limit=999999999` reads all of either one across the single
// connection every other query is queued behind.
func TestListAlertsClampsACallerSuppliedLimit(t *testing.T) {
	s, base := testStore(t)
	ctx := context.Background()

	const stored = defaultAlertRows + 50
	for i := range stored {
		if _, err := s.InsertAlert(ctx, model.Alert{
			Time: base, Detector: "portscan", Severity: model.SeverityWarning,
			Title: fmt.Sprintf("alert %d", i), Count: 1,
		}); err != nil {
			t.Fatalf("InsertAlert: %v", err)
		}
	}

	cases := []struct {
		name  string
		limit int
		want  int
	}{
		{"unset falls back to the default", 0, defaultAlertRows},
		{"a sane limit is honoured", 50, 50},
		{"at the ceiling everything stored comes back", alertRowCap, stored},
		{"above the ceiling falls back to the default", 1 << 30, defaultAlertRows},
		{"negative falls back to the default", -1, defaultAlertRows},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.ListAlerts(ctx, AlertFilter{Limit: tc.limit})
			if err != nil {
				t.Fatalf("ListAlerts: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("limit %d returned %d rows, want %d", tc.limit, len(got), tc.want)
			}
		})
	}
}
