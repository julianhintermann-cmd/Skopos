package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

func testConfig(t *testing.T, authMode string) *config.Config {
	t.Helper()
	c := config.Default()
	c.Server.Auth.Mode = authMode
	if authMode == "single_admin" {
		hash, _ := HashPassword("hunter2")
		c.Server.Auth.Username = "admin"
		c.Server.Auth.PasswordHash = hash
	}
	c.Server.Tokens = []config.APIToken{
		{Name: "reader", Token: "tok_read_aaaaaaaaaaaa", Scope: "read"},
		{Name: "writer", Token: "tok_write_bbbbbbbbbbbb", Scope: "write"},
	}
	return c
}

func newTestServer(t *testing.T, authMode string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "db"), Clock: func() time.Time { return time.Unix(1_700_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := testConfig(t, authMode)
	fw := firewall.NewService(firewall.Config{Enforce: false}, firewall.NewMemoryBackend(true), st, nil)
	disp := notify.New(notify.Options{})

	srv, err := New(Deps{
		Store: st, Firewall: fw, Notifier: disp, Config: cfg,
		Clock:  func() time.Time { return time.Unix(1_700_000_000, 0) },
		Health: func() Health { return Health{OK: true, Version: "test"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func do(t *testing.T, h http.Handler, method, path string, body string, cookies []*http.Cookie, headers map[string]string) *http.Response {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func TestHealthIsPublic(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	resp := do(t, srv.Handler(), "GET", "/api/health", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
}

func TestProtectedEndpointRequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	resp := do(t, srv.Handler(), "GET", "/api/overview", "", nil, nil)
	if resp.StatusCode != 401 {
		t.Errorf("unauthenticated overview = %d, want 401", resp.StatusCode)
	}
}

func TestLoginFlowAndSessionAccess(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")

	// Wrong password fails.
	resp := do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("bad login = %d, want 401", resp.StatusCode)
	}

	// Correct password sets a session cookie.
	resp = do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"hunter2"}`, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("good login = %d, want 200", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login did not set a session cookie")
	}

	// The cookie grants access to a protected endpoint.
	resp = do(t, srv.Handler(), "GET", "/api/overview", "", []*http.Cookie{cookie}, nil)
	if resp.StatusCode != 200 {
		t.Errorf("authenticated overview = %d, want 200", resp.StatusCode)
	}
}

func TestReadTokenCannotWrite(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	// Read token can read.
	resp := do(t, srv.Handler(), "GET", "/api/blocks", "", nil, map[string]string{"Authorization": "Bearer tok_read_aaaaaaaaaaaa"})
	if resp.StatusCode != 200 {
		t.Errorf("read token GET = %d, want 200", resp.StatusCode)
	}
	// Read token cannot write.
	resp = do(t, srv.Handler(), "POST", "/api/blocks", `{"prefix":"203.0.113.5"}`, nil,
		map[string]string{"Authorization": "Bearer tok_read_aaaaaaaaaaaa"})
	if resp.StatusCode != 403 {
		t.Errorf("read token POST = %d, want 403", resp.StatusCode)
	}
}

func TestWriteTokenBlocksAndUnblocks(t *testing.T) {
	srv, st := newTestServer(t, "single_admin")
	wr := map[string]string{"Authorization": "Bearer tok_write_bbbbbbbbbbbb"}

	resp := do(t, srv.Handler(), "POST", "/api/blocks", `{"prefix":"203.0.113.0/24","reason":"manual"}`, nil, wr)
	if resp.StatusCode != 201 {
		t.Fatalf("block = %d, want 201", resp.StatusCode)
	}
	active, _ := st.ActiveBlocks(context.Background())
	if len(active) != 1 {
		t.Fatalf("active blocks = %d, want 1", len(active))
	}

	resp = do(t, srv.Handler(), "DELETE", "/api/blocks?prefix=203.0.113.0/24", "", nil, wr)
	if resp.StatusCode != 200 {
		t.Errorf("unblock = %d, want 200", resp.StatusCode)
	}
}

func TestAuthNoneAllowsEverything(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	// No credentials, but auth is disabled: read and write both allowed.
	resp := do(t, srv.Handler(), "GET", "/api/overview", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Errorf("auth-none overview = %d, want 200", resp.StatusCode)
	}
	resp = do(t, srv.Handler(), "POST", "/api/blocks", `{"prefix":"203.0.113.5"}`, nil, nil)
	if resp.StatusCode != 201 {
		t.Errorf("auth-none block = %d, want 201", resp.StatusCode)
	}
}

func TestConfigValidateEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	// Valid config.
	resp := do(t, srv.Handler(), "POST", "/api/config/validate", "server:\n  port: 9000\n", nil, nil)
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["valid"] != true {
		t.Errorf("valid config reported invalid: %+v", out)
	}
	// Invalid config.
	resp = do(t, srv.Handler(), "POST", "/api/config/validate", "server:\n  port: 999999\n", nil, nil)
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["valid"] != false {
		t.Errorf("invalid config reported valid: %+v", out)
	}
}

func TestOpenAPISpecServed(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	resp := do(t, srv.Handler(), "GET", "/api/openapi.yaml", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("openapi = %d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "openapi: 3.1.0") {
		t.Error("spec does not look like OpenAPI 3.1")
	}
}

func TestLoginBackoff(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	// Several failed logins from the same client trip the limiter.
	var last int
	for i := 0; i < 4; i++ {
		resp := do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, nil)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests && last != http.StatusUnauthorized {
		t.Errorf("expected 429 or 401 under repeated failures, got %d", last)
	}
	// At least one should have been 429 once backoff engaged.
	got429 := false
	for i := 0; i < 6; i++ {
		resp := do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected backoff to produce a 429 after repeated failures")
	}
}

// The limiter counts failures per client, so whoever gets to name the client
// gets to decide whether it counts at all. X-Forwarded-For used to be read from
// any source: a fresh value on each attempt made every request a first offence
// and the threshold was never reached. Nothing about the header changed — it is
// still trivially set — so the fix is to disbelieve it unless the connection
// came from a proxy the operator configured, and this test spends ten forged
// identities to prove the limiter still counts to one.
func TestLoginLimiterIgnoresForwardedForFromUntrustedPeers(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")

	got429 := false
	for i := 0; i < 10; i++ {
		headers := map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i)}
		resp := do(t, srv.Handler(), "POST", "/api/auth/login",
			`{"username":"admin","password":"wrong"}`, nil, headers)
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("a new X-Forwarded-For per attempt walked past the login limiter")
	}
}

// Behind a real reverse proxy the header is the only way to tell two clients
// apart, so a configured proxy is still believed — otherwise the whole
// household would share one bucket and one attacker could lock everyone out.
func TestLoginLimiterHonoursForwardedForFromAConfiguredProxy(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	// httptest gives every request the same RemoteAddr, so trusting it makes
	// this server behave as if it sat behind a proxy at that address.
	srv.trustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

	// One client fails enough to be throttled.
	victim := map[string]string{"X-Forwarded-For": "203.0.113.7"}
	for i := 0; i < 10; i++ {
		do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, victim)
	}

	// A different client behind the same proxy must not inherit that penalty.
	other := map[string]string{"X-Forwarded-For": "203.0.113.8"}
	resp := do(t, srv.Handler(), "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, other)
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Error("a trusted proxy's clients were lumped into one bucket")
	}
}

// A CIDR that does not parse is a configuration the operator believes is
// protecting them. Starting anyway with the entry quietly dropped would leave
// them thinking their proxy is trusted while every client looks like the proxy.
func TestTrustedProxiesRefusesAMalformedRange(t *testing.T) {
	cfg := config.Default()
	cfg.Server.TrustedProxies = []string{"192.0.2.0/24", "not-a-cidr"}
	if _, err := New(Deps{Config: cfg}); err == nil {
		t.Fatal("expected a malformed trusted_proxies entry to be refused")
	}
}

// A failing kernel check must be reported without turning /api/health red.
//
// That endpoint drives the container healthcheck, and a 503 restarts the
// container. EnsureBase commits its teardown separately from its rebuild, so
// every restart widens the window in which the firewall table does not exist:
// wiring the kernel verdict into OK would answer a firewall that is not
// enforcing with a loop of restarts, each one leaving it not enforcing for
// longer. The check reports; reapplyAll repairs.
func TestHealthReportsKernelTroubleWithoutGoingUnhealthy(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	srv.deps.Health = func() Health {
		return Health{
			OK:        true,
			Version:   "test",
			Enforcing: true,
			Enforcement: &firewall.EnforcementState{
				Mode:    "enforce",
				Verdict: firewall.VerdictDegraded,
				Error:   "the blocks4 set is empty in the kernel",
			},
		}
	}

	resp := do(t, srv.Handler(), "GET", "/api/health", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a degraded kernel must not restart the container", resp.StatusCode)
	}
	var got Health
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Enforcement == nil {
		t.Fatal("the kernel verdict is missing: reporting it is the whole point")
	}
	if got.Enforcement.Verdict != firewall.VerdictDegraded {
		t.Errorf("verdict = %q, want %q", got.Enforcement.Verdict, firewall.VerdictDegraded)
	}
	if !got.OK {
		t.Error("ok = false: this is the restart loop the separation exists to prevent")
	}
}
