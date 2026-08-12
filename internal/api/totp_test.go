package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/totp"
)

// login posts credentials (and optionally an otp) and returns status + body.
func login(t *testing.T, srv *Server, body string) (int, map[string]any) {
	t.Helper()
	resp := do(t, srv.Handler(), "POST", "/api/auth/login", body, nil, nil)
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTOTPEnrollAndLogin(t *testing.T) {
	srv, _ := newTestServer(t, "single_admin")
	now := time.Unix(1_700_000_000, 0)

	// Sanity: login works without 2FA.
	if code, _ := login(t, srv, `{"username":"admin","password":"hunter2"}`); code != 200 {
		t.Fatalf("baseline login = %d", code)
	}

	// Setup stages a secret; a wrong code must not enable.
	resp := do(t, srv.Handler(), "POST", "/api/auth/totp/setup", "", nil,
		map[string]string{"Authorization": "Bearer tok_write_bbbbbbbbbbbb"})
	if resp.StatusCode != 200 {
		t.Fatalf("setup = %d", resp.StatusCode)
	}
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&setup)
	if setup.Secret == "" || setup.URI == "" {
		t.Fatalf("setup payload = %+v", setup)
	}

	wr := map[string]string{"Authorization": "Bearer tok_write_bbbbbbbbbbbb"}
	resp = do(t, srv.Handler(), "POST", "/api/auth/totp/enable", `{"code":"000000"}`, nil, wr)
	if resp.StatusCode != 401 {
		t.Fatalf("enable with wrong code = %d, want 401", resp.StatusCode)
	}

	good, _ := totp.Code(setup.Secret, now)
	resp = do(t, srv.Handler(), "POST", "/api/auth/totp/enable", fmt.Sprintf(`{"code":%q}`, good), nil, wr)
	if resp.StatusCode != 200 {
		t.Fatalf("enable = %d", resp.StatusCode)
	}

	// Password alone now asks for the second factor without burning backoff.
	code, out := login(t, srv, `{"username":"admin","password":"hunter2"}`)
	if code != 401 || out["otp_required"] != true {
		t.Fatalf("password-only login = %d %v, want otp_required", code, out)
	}
	// Wrong OTP fails.
	code, out = login(t, srv, `{"username":"admin","password":"hunter2","otp":"999999"}`)
	if code != 401 || out["otp_required"] != true {
		t.Fatalf("wrong otp = %d %v", code, out)
	}
	// Correct OTP logs in.
	code, _ = login(t, srv, fmt.Sprintf(`{"username":"admin","password":"hunter2","otp":%q}`, good))
	if code != 200 {
		t.Fatalf("otp login = %d, want 200", code)
	}

	// Status reflects the enrollment; disable needs a live code too.
	resp = do(t, srv.Handler(), "GET", "/api/auth/totp", "", nil, wr)
	var st struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if !st.Enabled {
		t.Error("status should report enabled")
	}
	resp = do(t, srv.Handler(), "POST", "/api/auth/totp/disable", fmt.Sprintf(`{"code":%q}`, good), nil, wr)
	if resp.StatusCode != 200 {
		t.Fatalf("disable = %d", resp.StatusCode)
	}
	if code, _ := login(t, srv, `{"username":"admin","password":"hunter2"}`); code != 200 {
		t.Errorf("login after disable = %d, want 200", code)
	}
}

func TestTOTPSetupRejectedWhenAuthOff(t *testing.T) {
	srv, _ := newTestServer(t, "none")
	resp := do(t, srv.Handler(), "POST", "/api/auth/totp/setup", "", nil, nil)
	if resp.StatusCode != 400 {
		t.Errorf("setup with auth none = %d, want 400", resp.StatusCode)
	}
	if resp2 := do(t, srv.Handler(), "GET", "/api/auth/totp", "", nil, nil); resp2.StatusCode == 200 {
		var st struct {
			Supported bool `json:"supported"`
		}
		_ = json.NewDecoder(resp2.Body).Decode(&st)
		if st.Supported {
			t.Error("2FA must report unsupported when auth is off")
		}
	}
}
