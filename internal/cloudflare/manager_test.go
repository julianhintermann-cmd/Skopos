package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/secret"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func testManager(t *testing.T, h http.Handler) (*Manager, *store.Store, *httptest.Server) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "cf.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	box, err := secret.FromStore(st)
	if err != nil {
		t.Fatal(err)
	}
	c, srv := testClient(h)
	t.Cleanup(srv.Close)
	return NewManager(st, box, c, time.Now), st, srv
}

// cfMux returns a handler that answers verify, zones and graphql.
func cfMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"tok1","status":"active","expires_on":""}}`))
	})
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":[
			{"id":"z1","name":"example.com","status":"active"},
			{"id":"z2","name":"example.net","status":"active"}
		],"result_info":{"page":1,"total_pages":1}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"viewer":{"zones":[{"httpRequests1hGroups":[
			{"dimensions":{"datetime":"2026-08-12T10:00:00Z"},"sum":{"requests":10,"bytes":100,"cachedRequests":1,"cachedBytes":10,"threats":0}}
		]}]}}}`))
	})
	return mux
}

func TestManagerConnectStatusDisconnect(t *testing.T) {
	m, st, _ := testManager(t, cfMux())
	ctx := context.Background()

	// Not connected initially.
	if s, _ := m.Status(ctx); s.Connected {
		t.Fatal("should start disconnected")
	}

	status, err := m.Connect(ctx, "my-token")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Connected || len(status.Zones) != 2 || status.TokenID != "tok1" {
		t.Fatalf("status after connect = %+v", status)
	}

	// The token is stored sealed, never in the clear.
	sealed, ok, _ := st.CFToken()
	if !ok || sealed == "my-token" {
		t.Fatalf("token not sealed: %q", sealed)
	}

	// Toggle a zone off; it survives a Status round-trip.
	if err := m.SetMonitored(ctx, "z2", false); err != nil {
		t.Fatal(err)
	}
	status, _ = m.Status(ctx)
	var z2 ZoneView
	for _, z := range status.Zones {
		if z.ID == "z2" {
			z2 = z
		}
	}
	if z2.Monitored {
		t.Error("z2 should be unmonitored after toggle")
	}

	ids, _ := m.MonitoredZones(ctx)
	if len(ids) != 1 || ids[0] != "z1" {
		t.Errorf("monitored zones = %v, want [z1]", ids)
	}

	if err := m.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := m.Status(ctx); s.Connected || len(s.Zones) != 0 {
		t.Errorf("after disconnect: %+v", s)
	}
}

func TestManagerConnectPreservesMonitoredOnRefresh(t *testing.T) {
	m, _, _ := testManager(t, cfMux())
	ctx := context.Background()

	if _, err := m.Connect(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetMonitored(ctx, "z1", false); err != nil {
		t.Fatal(err)
	}
	// Reconnect (refresh) must not silently re-enable a zone turned off.
	if _, err := m.Connect(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	status, _ := m.Status(ctx)
	for _, z := range status.Zones {
		if z.ID == "z1" && z.Monitored {
			t.Error("refresh re-enabled a disabled zone")
		}
	}
}

func TestManagerAnalyticsRequiresConnection(t *testing.T) {
	m, _, _ := testManager(t, cfMux())
	if _, err := m.Analytics(context.Background(), "z1", time.Hour); err == nil {
		t.Error("analytics without a token should error")
	}
}

func TestManagerAnalyticsCaches(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens/verify", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"t","status":"active"}}`))
	})
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"x.com","status":"active"}],"result_info":{"page":1,"total_pages":1}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":{"viewer":{"zones":[{"httpRequests1hGroups":[]}]}}}`))
	})
	m, _, _ := testManager(t, mux)
	ctx := context.Background()
	if _, err := m.Connect(ctx, "t"); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := m.Analytics(ctx, "z1", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("graphql calls = %d, want 1 (cached)", calls)
	}
}
