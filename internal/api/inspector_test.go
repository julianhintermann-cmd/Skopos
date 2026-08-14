package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/notify"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// unreadableBackend can do everything the memory backend can except read the
// kernel back, which is the one failure this endpoint has to get right.
type unreadableBackend struct{ *firewall.MemoryBackend }

func (unreadableBackend) Dump(context.Context) (firewall.Snapshot, error) {
	return firewall.Snapshot{}, errors.New("opening netlink: operation not permitted")
}

func inspectorServer(t *testing.T, backend firewall.Backend) (*Server, *store.Store) {
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
	return srv, st
}

// A dump that failed must not ship a snapshot key. An empty object would render
// as a table that is gone and fourteen sets holding nothing — the most alarming
// thing this endpoint can say, and the one thing it must never say without
// having read it.
func TestKernelDumpFailureShipsNoSnapshot(t *testing.T) {
	srv, _ := inspectorServer(t, unreadableBackend{firewall.NewMemoryBackend(true)})
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if v, ok := body["snapshot"]; ok {
		t.Errorf("snapshot = %v after a failed read", v)
	}
	if msg, _ := body["error"].(string); msg == "" {
		t.Errorf("no reason given: %v", body)
	}
}

func TestKernelDumpServesTheKernelAndTheIntent(t *testing.T) {
	srv, _ := inspectorServer(t, firewall.NewMemoryBackend(true))
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
	if snap["read_at"] == nil {
		t.Error("a snapshot with no read time cannot be aged by the view")
	}
	for _, key := range []string{"enforcement", "intent"} {
		if _, ok := body[key]; !ok {
			t.Errorf("%s missing: %v", key, body)
		}
	}
}

// Intent absent is not intent empty: without it every set looks agreed-upon,
// which is the disagreement this endpoint was built to surface.
func TestKernelDumpOmitsIntentItCouldNotRead(t *testing.T) {
	srv, st := inspectorServer(t, firewall.NewMemoryBackend(true))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	if v, ok := body["intent"]; ok {
		t.Errorf("intent = %v after a failed read; it must be omitted", v)
	}
	missing, _ := body["unavailable"].([]any)
	if len(missing) != 1 || missing[0] != "intent" {
		t.Errorf("unavailable = %v", body["unavailable"])
	}
	if _, ok := body["snapshot"]; !ok {
		t.Errorf("the kernel read succeeded and its snapshot went missing: %v", body)
	}
}

func TestKernelDumpNeedsAReadToken(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	if resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	resp := do(t, srv.Handler(), "GET", "/api/firewall/kernel", "", nil,
		map[string]string{"Authorization": "Bearer tok_read_aaaaaaaaaaaa"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read token status = %d, want 200", resp.StatusCode)
	}
}
