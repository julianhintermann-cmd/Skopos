package api

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/model"
)

func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reputation == nil {
		writeError(w, http.StatusNotImplemented, "reputation unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	info, err := s.deps.Reputation.Lookup(ctx, addr)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleAbuseIPDBStatus(w http.ResponseWriter, r *http.Request) {
	configured := s.deps.Reputation != nil && s.deps.Reputation.HasAbuseKey()
	writeJSON(w, http.StatusOK, map[string]any{"configured": configured})
}

func (s *Server) handleAbuseIPDBConnect(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reputation == nil {
		writeError(w, http.StatusNotImplemented, "reputation unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Key string `json:"key"`
	}
	if err := decodeJSON(w, r, &req); err != nil || strings.TrimSpace(req.Key) == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	if err := s.deps.Reputation.SetAbuseKey(ctx, req.Key); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "abuseipdb_connect"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": true})
}

func (s *Server) handleAbuseIPDBDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reputation == nil {
		writeError(w, http.StatusNotImplemented, "reputation unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.deps.Reputation.DeleteAbuseKey(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "abuseipdb_disconnect"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": false})
}
