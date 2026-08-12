package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/cloudflare"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// fakeCF is a scripted CloudflareService for handler tests.
type fakeCF struct {
	status       cloudflare.Status
	connectErr   error
	lastToken    string
	analyticsErr error
	setErr       error
	lastZone     string
	lastMonitor  bool
}

func (f *fakeCF) Status(context.Context) (cloudflare.Status, error) { return f.status, nil }
func (f *fakeCF) Connect(_ context.Context, token string) (cloudflare.Status, error) {
	f.lastToken = token
	if f.connectErr != nil {
		return cloudflare.Status{}, f.connectErr
	}
	f.status = cloudflare.Status{Connected: true, TokenID: "tok", Zones: []cloudflare.ZoneView{{ID: "z1", Name: "ex.com", Monitored: true}}}
	return f.status, nil
}
func (f *fakeCF) Disconnect(context.Context) error {
	f.status = cloudflare.Status{Zones: []cloudflare.ZoneView{}}
	return nil
}
func (f *fakeCF) SetMonitored(_ context.Context, zoneID string, on bool) error {
	f.lastZone, f.lastMonitor = zoneID, on
	return f.setErr
}
func (f *fakeCF) Analytics(context.Context, string, time.Duration) (cloudflare.AnalyticsSeries, error) {
	if f.analyticsErr != nil {
		return cloudflare.AnalyticsSeries{}, f.analyticsErr
	}
	return cloudflare.AnalyticsSeries{ZoneID: "z1", Points: []cloudflare.AnalyticsPoint{{Requests: 5}}}, nil
}

func cfServer(t *testing.T, cf CloudflareService) *Server {
	t.Helper()
	st, err := store.Open(store.Options{Path: t.TempDir() + "/db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := config.Default()
	cfg.Server.Auth.Mode = "none"
	fw := firewall.NewService(firewall.Config{}, firewall.NewMemoryBackend(true), st, nil)
	srv, err := New(Deps{Store: st, Firewall: fw, Notifier: notify.New(notify.Options{}), Config: cfg, Cloudflare: cf})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestCFStatusAndConnect(t *testing.T) {
	cf := &fakeCF{status: cloudflare.Status{Zones: []cloudflare.ZoneView{}}}
	srv := cfServer(t, cf)

	// Initially disconnected.
	resp := do(t, srv.Handler(), "GET", "/api/integrations/cloudflare", "", nil, nil)
	var st cloudflare.Status
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st.Connected {
		t.Fatal("should start disconnected")
	}

	// Connect passes the token through and returns the new status.
	resp = do(t, srv.Handler(), "POST", "/api/integrations/cloudflare", `{"token":"abc"}`, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("connect = %d, want 200", resp.StatusCode)
	}
	if cf.lastToken != "abc" {
		t.Errorf("token forwarded = %q, want abc", cf.lastToken)
	}
}

func TestCFConnectRejectsEmptyAndSurfacesError(t *testing.T) {
	srv := cfServer(t, &fakeCF{})
	resp := do(t, srv.Handler(), "POST", "/api/integrations/cloudflare", `{"token":"  "}`, nil, nil)
	if resp.StatusCode != 400 {
		t.Errorf("empty token = %d, want 400", resp.StatusCode)
	}

	srv = cfServer(t, &fakeCF{connectErr: errors.New("token rejected")})
	resp = do(t, srv.Handler(), "POST", "/api/integrations/cloudflare", `{"token":"bad"}`, nil, nil)
	if resp.StatusCode != 502 {
		t.Errorf("bad token = %d, want 502", resp.StatusCode)
	}
}

func TestCFSetZoneNotFound(t *testing.T) {
	srv := cfServer(t, &fakeCF{setErr: store.ErrZoneNotFound})
	resp := do(t, srv.Handler(), "POST", "/api/integrations/cloudflare/zones/zX", `{"monitored":false}`, nil, nil)
	if resp.StatusCode != 404 {
		t.Errorf("unknown zone = %d, want 404", resp.StatusCode)
	}
}

func TestCFSetZoneOK(t *testing.T) {
	cf := &fakeCF{}
	srv := cfServer(t, cf)
	resp := do(t, srv.Handler(), "POST", "/api/integrations/cloudflare/zones/z1", `{"monitored":false}`, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("set zone = %d, want 200", resp.StatusCode)
	}
	if cf.lastZone != "z1" || cf.lastMonitor {
		t.Errorf("set zone args = %q/%v, want z1/false", cf.lastZone, cf.lastMonitor)
	}
}

func TestCFAnalytics(t *testing.T) {
	srv := cfServer(t, &fakeCF{})
	// Missing zone → 400.
	resp := do(t, srv.Handler(), "GET", "/api/integrations/cloudflare/analytics", "", nil, nil)
	if resp.StatusCode != 400 {
		t.Errorf("missing zone = %d, want 400", resp.StatusCode)
	}
	// With zone → 200 and a series.
	resp = do(t, srv.Handler(), "GET", "/api/integrations/cloudflare/analytics?zone=z1&window=24h", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("analytics = %d, want 200", resp.StatusCode)
	}
	var series cloudflare.AnalyticsSeries
	_ = json.NewDecoder(resp.Body).Decode(&series)
	if len(series.Points) != 1 {
		t.Errorf("series points = %d, want 1", len(series.Points))
	}
}

func TestCFAnalyticsUpstreamError(t *testing.T) {
	srv := cfServer(t, &fakeCF{analyticsErr: errors.New("not authorized")})
	resp := do(t, srv.Handler(), "GET", "/api/integrations/cloudflare/analytics?zone=z1", "", nil, nil)
	if resp.StatusCode != 502 {
		t.Errorf("upstream error = %d, want 502", resp.StatusCode)
	}
}
