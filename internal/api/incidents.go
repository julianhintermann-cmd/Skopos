package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// handleIncidents lists alert episodes: one row per source per burst of
// activity, instead of one row per alert.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	f := store.IncidentFilter{UnackedOnly: r.URL.Query().Get("unacked") == "true"}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	incidents, err := s.deps.Store.ListIncidents(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": incidents})
}

// handleIncident returns one episode with its alerts.
func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid incident id")
		return
	}
	incident, err := s.deps.Store.IncidentByID(ctx, id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "no such incident")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, incident)
}

// handleAckIncident acknowledges an episode and every alert inside it.
func (s *Server) handleAckIncident(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid incident id")
		return
	}
	if err := s.deps.Store.AckIncident(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleListMutes returns the operator's suppression rules.
func (s *Server) handleListMutes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	rules, err := s.deps.Store.ListMuteRules(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// handleAddMute creates a suppression rule. Muting silences the alert and the
// notification, never the block — the response says so, because a rule that
// quietly disarmed protection would be a trap.
func (s *Server) handleAddMute(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	var req struct {
		Detector string `json:"detector"`
		Prefix   string `json:"prefix"`
		Port     int    `json:"port"`
		Reason   string `json:"reason"`
		TTL      string `json:"ttl"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rule := store.MuteRule{
		Detector: strings.TrimSpace(req.Detector),
		Port:     req.Port,
		Reason:   strings.TrimSpace(req.Reason),
	}
	// A bare address is accepted and normalised to a host prefix, so the
	// operator can paste what the alert showed them.
	if p := strings.TrimSpace(req.Prefix); p != "" {
		prefix, err := parsePrefixOrIP(p)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid prefix: "+err.Error())
			return
		}
		rule.Prefix = prefix.String()
	}
	if req.TTL != "" {
		d, err := config.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ttl: "+err.Error())
			return
		}
		t := s.clock().Add(d.Std())
		rule.Expires = &t
	}

	created, err := s.deps.Store.AddMuteRule(ctx, rule)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.reloadMutes()

	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "mute_add", Target: muteTarget(created), Detail: created.Reason,
	})
	writeJSON(w, http.StatusCreated, created)
}

// handleDeleteMute removes a suppression rule.
func (s *Server) handleDeleteMute(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	removed, err := s.deps.Store.DeleteMuteRule(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "no such rule")
		return
	}
	s.reloadMutes()

	who, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: who.name, Action: "mute_delete", Target: strconv.FormatInt(id, 10),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// reloadMutes pushes the stored rules into the live policy engine.
func (s *Server) reloadMutes() {
	if s.deps.ReloadMutes != nil {
		s.deps.ReloadMutes()
	}
}

func muteTarget(r store.MuteRule) string {
	parts := make([]string, 0, 3)
	if r.Detector != "" {
		parts = append(parts, r.Detector)
	}
	if r.Prefix != "" {
		parts = append(parts, r.Prefix)
	}
	if r.Port != 0 {
		parts = append(parts, "port "+strconv.Itoa(r.Port))
	}
	return strings.Join(parts, " ")
}
