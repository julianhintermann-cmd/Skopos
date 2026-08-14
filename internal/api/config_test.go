package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// A configuration file that was never read is the most consequential mistake
// an operator can make and the least visible one: Skopos falls back to
// defaults, every screen looks entirely normal, and the settings on display
// are not the ones in their file. The endpoint has to say so.
func TestConfigReportsAMissingFileAsMissing(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	srv.deps.ConfigInfo = config.LoadInfo{Path: "/config/config.yaml", Missing: true}

	resp := do(t, srv.Handler(), "GET", "/api/config", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got ConfigReport
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Found {
		t.Error("a missing file reported as found — this is the mistyped-mount case")
	}
	if got.Path == "" {
		t.Error("the path is what makes a bad mount actionable and must always be present")
	}
}

// An inert key is one the operator wrote down expecting an effect. Naming the
// ones in their own file is the point; listing every inert key on every
// install would be noise.
func TestConfigNamesTheInertKeysAndWhy(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	srv.deps.ConfigInfo = config.LoadInfo{
		Path:  "/config/config.yaml",
		Inert: []string{"capture.rdns"},
	}

	resp := do(t, srv.Handler(), "GET", "/api/config", "", nil, nil)
	var got ConfigReport
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Inert) != 1 || got.Inert[0] != "capture.rdns" {
		t.Fatalf("inert keys = %v, want [capture.rdns]", got.Inert)
	}
	if got.InertReasons["capture.rdns"] == "" {
		t.Error("an inert key without a reason leaves the reader to guess why it does nothing")
	}
}

// Whether a notifier is set up is reportable. What it is set up with is not:
// the ntfy token lives in the environment and must never reach a response.
func TestConfigNeverCarriesTheNtfyToken(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	srv.deps.Config.Notify.Ntfy.URL = "https://ntfy.sh"
	srv.deps.Config.Notify.Ntfy.Topic = "skopos-alerts"
	srv.deps.Config.Notify.Ntfy.Token = "tk_secret_do_not_leak"

	resp := do(t, srv.Handler(), "GET", "/api/config", "", nil, nil)
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !contains(body, "\"configured\":true") {
		t.Errorf("a fully configured ntfy reported as unconfigured: %s", body)
	}
	if contains(body, "tk_secret_do_not_leak") {
		t.Fatal("the ntfy token reached the response body")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
