package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// Temporary verification of GET /api/firewall/kernel. Deleted before hand-off:
// test files are outside this task's file boundary.

type unreadableBackend struct{ *firewall.MemoryBackend }

func (unreadableBackend) Dump(context.Context) (firewall.Snapshot, error) {
	return firewall.Snapshot{}, errors.New("opening netlink: operation not permitted")
}

func scratchServer(t *testing.T, backend firewall.Backend) *Server {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	srv, err := New(Deps{
		Store: st, Config: testConfig(t, "none"), Notifier: notify.New(notify.Options{}),
		Firewall: firewall.NewService(firewall.Config{Enforce: true}, backend, st, nil),
		Clock:    func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func TestScratchKernelDumpFailureHasNoSnapshot(t *testing.T) {
	srv := scratchServer(t, unreadableBackend{firewall.NewMemoryBackend(true)})
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if _, ok := body["snapshot"]; ok {
		t.Errorf("a failed read shipped a snapshot: %v", body["snapshot"])
	}
	if body["error"] == "" || body["error"] == nil {
		t.Errorf("no reason given: %v", body)
	}
}

func TestScratchKernelDumpServesTheSets(t *testing.T) {
	srv := scratchServer(t, firewall.NewMemoryBackend(true))
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	snap, ok := body["snapshot"].(map[string]any)
	if !ok {
		t.Fatalf("no snapshot: %v", body)
	}
	sets, _ := snap["sets"].([]any)
	chains, _ := snap["chains"].([]any)
	if len(sets) != 14 || len(chains) != 3 {
		t.Fatalf("sets = %d chains = %d", len(sets), len(chains))
	}
	if _, ok := body["enforcement"]; !ok {
		t.Errorf("no enforcement state alongside the snapshot")
	}
	if _, ok := body["intent"]; !ok {
		t.Errorf("no intent: %v", body)
	}
	pretty, _ := json.MarshalIndent(map[string]any{
		"snapshot":    map[string]any{"read_at": snap["read_at"], "table": snap["table"], "chains": chains, "sets": sets[:2]},
		"enforcement": body["enforcement"],
		"intent":      body["intent"],
	}, "", "  ")
	t.Logf("payload:\n%s", pretty)
}

func TestScratchKernelDumpNeedsAuth(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp = do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil,
		map[string]string{"Authorization": "Bearer tok_read_aaaaaaaaaaaa"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read token status = %d, want 200", resp.StatusCode)
	}
}
