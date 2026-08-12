package api

import (
	"net/http"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/totp"
)

// TOTP state lives in the meta table, like the session signing key: the
// pending secret during setup, the active secret, and the enabled flag.
const (
	totpSecretMeta  = "totp_secret"
	totpPendingMeta = "totp_pending"
	totpEnabledMeta = "totp_enabled"
)

func (s *Server) totpEnabled() bool {
	v, ok, err := s.deps.Store.GetMeta(totpEnabledMeta)
	return err == nil && ok && v == "1"
}

func (s *Server) totpSecret() string {
	v, _, _ := s.deps.Store.GetMeta(totpSecretMeta)
	return v
}

// handleTOTPStatus reports whether 2FA is supported (auth is on) and enabled.
func (s *Server) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"supported": !s.authOff,
		"enabled":   s.totpEnabled(),
	})
}

// handleTOTPSetup starts enrollment: a fresh secret, staged until a correct
// code proves the authenticator actually has it.
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if s.authOff {
		writeError(w, http.StatusBadRequest, "authentication is disabled — 2FA needs auth mode single_admin")
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.deps.Store.SetMeta(totpPendingMeta, secret); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    totp.URI(secret, s.deps.Config.Server.Auth.Username, "Skopos"),
	})
}

// handleTOTPEnable confirms enrollment with a live code.
func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pending, ok, _ := s.deps.Store.GetMeta(totpPendingMeta)
	if !ok || pending == "" {
		writeError(w, http.StatusBadRequest, "no setup in progress — call setup first")
		return
	}
	if !totp.Verify(pending, req.Code, s.clock()) {
		writeError(w, http.StatusUnauthorized, "wrong code — check the authenticator and try again")
		return
	}
	if err := s.deps.Store.SetMeta(totpSecretMeta, pending); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.deps.Store.SetMeta(totpPendingMeta, "")
	if err := s.deps.Store.SetMeta(totpEnabledMeta, "1"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "totp_enabled"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": true})
}

// handleTOTPDisable turns 2FA off, gated on a live code so a stolen session
// alone cannot silently weaken the login.
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !s.totpEnabled() {
		writeError(w, http.StatusBadRequest, "2FA is not enabled")
		return
	}
	if !totp.Verify(s.totpSecret(), req.Code, s.clock()) {
		writeError(w, http.StatusUnauthorized, "wrong code")
		return
	}
	_ = s.deps.Store.SetMeta(totpEnabledMeta, "")
	_ = s.deps.Store.SetMeta(totpSecretMeta, "")
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "totp_disabled"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": false})
}
