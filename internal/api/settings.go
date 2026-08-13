package api

import (
	"encoding/json"
	"net/http"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/settings"
)

// SettingsManager is the runtime settings surface the API needs.
type SettingsManager interface {
	Current() settings.Runtime
	Base() settings.Runtime
	Overridden() []string
	Update(patch map[string]json.RawMessage) error
	Reset() error
}

// handleGetSettings returns the effective settings, the YAML baseline and
// which fields the operator has overridden — enough for the UI to show what
// is coming from the file and what is not.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Settings == nil {
		writeError(w, http.StatusNotImplemented, "runtime settings unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"effective":  s.deps.Settings.Current(),
		"base":       s.deps.Settings.Base(),
		"overridden": s.deps.Settings.Overridden(),
	})
}

// handleUpdateSettings applies a patch of field paths. Rejected patches
// change nothing, so a bad value can never leave the firewall half-armed.
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Settings == nil {
		writeError(w, http.StatusNotImplemented, "runtime settings unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	var patch map[string]json.RawMessage
	if err := decodeJSON(w, r, &patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(patch) == 0 {
		writeError(w, http.StatusBadRequest, "no settings in request")
		return
	}
	if err := s.deps.Settings.Update(patch); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	id, _ := identityFrom(r)
	keys := make([]string, 0, len(patch))
	for k := range patch {
		keys = append(keys, k)
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "settings_update", Detail: joinSorted(keys),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"effective":  s.deps.Settings.Current(),
		"overridden": s.deps.Settings.Overridden(),
	})
}

// handleResetSettings drops every override, returning to the YAML file.
func (s *Server) handleResetSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Settings == nil {
		writeError(w, http.StatusNotImplemented, "runtime settings unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	if err := s.deps.Settings.Reset(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "settings_reset", Detail: "back to config.yaml",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "effective": s.deps.Settings.Current(),
	})
}
