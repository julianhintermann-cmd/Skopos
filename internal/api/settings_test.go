package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/settings"
)

// refusingBackend is a kernel that will not take the base ruleset: an
// unprivileged container, a host that will not let nftables be programmed.
// Everything else about it is the real memory backend.
type refusingBackend struct{ *firewall.MemoryBackend }

func (refusingBackend) EnsureBase(context.Context) error {
	return errors.New("ensuring base ruleset: operation not permitted")
}

func settingsBaseline() settings.Runtime {
	return settings.Runtime{
		Enforcement: "observe",
		BlockTTL:    24 * time.Hour,
		Cooldown:    30 * time.Minute,
		Portscan: settings.Portscan{
			Enabled: true, Window: time.Minute,
			External: settings.Thresholds{Ports: 15, Targets: 10},
			Internal: settings.Thresholds{Ports: 40, Targets: 25},
		},
		Rate: settings.Rate{Enabled: true, Window: 10 * time.Second, MaxNewConnections: 200, MaxPacketsPerSecond: 5000},
	}
}

// settingsServer wires the real settings manager to a real firewall service
// over the given backend, through the same apply subscriber the runtime uses.
// Only the kernel underneath is substituted; every layer being tested is the
// shipping one.
func settingsServer(t *testing.T, backend firewall.Backend) *Server {
	t.Helper()
	srv, st := newTestServer(t, "none")
	fw := firewall.NewService(firewall.Config{}, backend, st, nil)
	setman, err := settings.New(st, settingsBaseline())
	if err != nil {
		t.Fatal(err)
	}
	setman.OnApply(func(r settings.Runtime) settings.ApplyResult {
		var res settings.ApplyResult
		res.Fail("enforcement", fw.SetEnforce(context.Background(), r.Enforcement == "enforce"))
		return res
	})
	srv.deps.Firewall = fw
	srv.deps.Settings = setman
	return srv
}

func auditActions(t *testing.T, srv *Server) map[string]string {
	t.Helper()
	rows, err := srv.deps.Store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range rows {
		out[e.Action] = e.Detail
	}
	return out
}

// The defect this endpoint exists to stop: the operator arms the firewall, the
// kernel refuses, and the page says armed while nothing is being dropped.
func TestSettingsRefusedByTheKernelAnswers202(t *testing.T) {
	srv := settingsServer(t, refusingBackend{firewall.NewMemoryBackend(true)})

	resp := do(t, srv.Handler(), "POST", "/api/settings", `{"enforcement":"enforce"}`, nil, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 — the setting was stored but the kernel refused it", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if body["ok"] != false {
		t.Errorf("ok = %v; a refused apply must never be reported as a success", body["ok"])
	}
	if body["stored"] != true {
		t.Errorf("stored = %v; the intent is persisted and the verify loop retries it", body["stored"])
	}

	applied, _ := body["applied"].(map[string]any)
	if applied == nil || applied["ok"] != false {
		t.Fatalf("applied = %v, want ok:false", body["applied"])
	}
	errs, _ := applied["errors"].([]any)
	if len(errs) != 1 {
		t.Fatalf("applied.errors = %v, want the kernel's reason", applied["errors"])
	}
	first, _ := errs[0].(map[string]any)
	if first["field"] != "enforcement" || first["message"] == "" {
		t.Errorf("applied.errors[0] = %v, want the field and the reason", first)
	}

	// The read-back, not the request. SetEnforce leaves the mode where it
	// actually ended up, and that is what has to be on the wire.
	enf, _ := body["enforcement"].(map[string]any)
	if enf == nil {
		t.Fatal("no enforcement block: reporting what the firewall says about itself is the point")
	}
	if enf["mode"] != "observe" || enf["verdict"] != string(firewall.VerdictObserving) {
		t.Errorf("enforcement = %v; the arming failed, so the state must not echo the request", enf)
	}

	eff, _ := body["effective"].(map[string]any)
	if eff["enforcement"] != "enforce" {
		t.Errorf("effective.enforcement = %v, want the stored intent kept", eff["enforcement"])
	}
	if detail := auditActions(t, srv)["settings_apply_failed"]; detail == "" {
		t.Error("no settings_apply_failed audit row: the unprotected window left no trace")
	}
}

// The same lie without an error to catch it. An unavailable backend records
// the desired mode and returns nil, so nothing in the apply path complains —
// the only thing that knows is the firewall's own verdict, read afterwards.
func TestSettingsUnableKernelIsNot200(t *testing.T) {
	srv := settingsServer(t, firewall.NewMemoryBackend(false))

	resp := do(t, srv.Handler(), "POST", "/api/settings", `{"enforcement":"enforce"}`, nil, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 — enforce was stored over a backend that cannot enforce", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if body["ok"] != false {
		t.Errorf("ok = %v, want false", body["ok"])
	}
	applied, _ := body["applied"].(map[string]any)
	if applied["ok"] != true {
		t.Errorf("applied.ok = %v; nothing refused the call, and the status must still not be 200", applied["ok"])
	}
	enf, _ := body["enforcement"].(map[string]any)
	if enf["verdict"] != string(firewall.VerdictUnable) {
		t.Errorf("verdict = %v, want %q", enf["verdict"], firewall.VerdictUnable)
	}
}

// A change the kernel does take answers 200 — and still ships the verdict, so
// the caller learns that the read-back has not happened yet rather than being
// handed a green light the endpoint has no evidence for.
func TestSettingsAppliedAnswers200WithTheVerdict(t *testing.T) {
	srv := settingsServer(t, firewall.NewMemoryBackend(true))

	resp := do(t, srv.Handler(), "POST", "/api/settings", `{"enforcement":"enforce"}`, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the kernel took it", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if body["ok"] != true {
		t.Errorf("ok = %v, want true", body["ok"])
	}
	enf, _ := body["enforcement"].(map[string]any)
	if enf["mode"] != "enforce" {
		t.Errorf("mode = %v, want enforce", enf["mode"])
	}
	if enf["verdict"] != string(firewall.VerdictUnverified) {
		t.Errorf("verdict = %v, want %q: the writes went in, nobody has read the kernel back yet",
			enf["verdict"], firewall.VerdictUnverified)
	}
	if _, ok := enf["checked_at"]; ok {
		t.Error("checked_at is present with no read behind it")
	}
	if a := auditActions(t, srv); a["settings_apply_failed"] != "" {
		t.Errorf("a successful apply wrote settings_apply_failed: %q", a["settings_apply_failed"])
	}
}

// Reset goes back to the file through the same apply path, so it answers from
// the same read-back: the machine that could not enforce a moment ago can
// observe, and the response has to say so rather than inherit the 202.
func TestResetAnswersFromTheReadBackToo(t *testing.T) {
	srv := settingsServer(t, firewall.NewMemoryBackend(false))
	// Arm first so that resetting to the observe baseline is a real change.
	if resp := do(t, srv.Handler(), "POST", "/api/settings", `{"enforcement":"enforce"}`, nil, nil); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("arming = %d, want 202", resp.StatusCode)
	}

	resp := do(t, srv.Handler(), "DELETE", "/api/settings", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the baseline is observe, which any backend holds", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	enf, _ := body["enforcement"].(map[string]any)
	if enf["verdict"] != string(firewall.VerdictObserving) {
		t.Errorf("verdict = %v, want %q", enf["verdict"], firewall.VerdictObserving)
	}
}

// The settings page must open on the kernel's answer, not on the file's.
func TestGetSettingsCarriesTheEnforcementState(t *testing.T) {
	srv := settingsServer(t, firewall.NewMemoryBackend(true))
	body := decodeBody(t, do(t, srv.Handler(), "GET", "/api/settings", "", nil, nil))
	enf, _ := body["enforcement"].(map[string]any)
	if enf == nil || enf["verdict"] == "" {
		t.Fatalf("enforcement = %v, want the firewall's verdict", body["enforcement"])
	}
}
