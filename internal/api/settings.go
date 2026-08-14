package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/settings"
)

// SettingsManager is the runtime settings surface the API needs.
//
// Update and Reset return two answers on purpose. The error says the change
// was refused and nothing was stored; the ApplyResult says it was stored and
// what the live subsystems then made of it. Collapsing those into one bool is
// what let this endpoint report a success the kernel never gave it.
type SettingsManager interface {
	Current() settings.Runtime
	Base() settings.Runtime
	Overridden() []string
	Update(patch map[string]json.RawMessage) (settings.ApplyResult, error)
	Reset() (settings.ApplyResult, error)
}

// handleGetSettings returns the effective settings, the YAML baseline and
// which fields the operator has overridden — enough for the UI to show what
// is coming from the file and what is not. The firewall's own verdict rides
// along so the page opens on what the kernel holds rather than on what the
// settings ask for.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Settings == nil {
		writeError(w, http.StatusNotImplemented, "runtime settings unavailable")
		return
	}
	body := map[string]any{
		"effective":  s.deps.Settings.Current(),
		"base":       s.deps.Settings.Base(),
		"overridden": s.deps.Settings.Overridden(),
	}
	if st := s.enforcementNow(); st != nil {
		body["enforcement"] = st
	}
	writeJSON(w, http.StatusOK, body)
}

// handleUpdateSettings applies a patch of field paths. Rejected patches
// change nothing, so a bad value can never leave the firewall half-armed.
//
// A patch that is stored but that the kernel will not take answers 202, never
// 200: see writeApplied.
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
	applied, err := s.deps.Settings.Update(patch)
	if err != nil {
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
	s.writeApplied(ctx, w, id.name, applied, map[string]any{
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

	applied, err := s.deps.Settings.Reset()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "settings_reset", Detail: "back to config.yaml",
	})
	// Going back to the file is a kernel change like any other, and it can be
	// refused like any other.
	s.writeApplied(ctx, w, id.name, applied, map[string]any{
		"effective": s.deps.Settings.Current(),
	})
}

// writeApplied answers with what actually happened.
//
//	200 — stored, and the firewall came out in the state the settings ask for.
//	202 — stored, but it is not in effect. The intent is kept on purpose: the
//	      operator meant it and the verify loop keeps retrying, so discarding
//	      it would be its own kind of wrong.
//
// The body carries three separate facts and never merges them: whether the
// override was persisted (stored), what the subsystems reported back
// (applied), and what the firewall says about itself now that the attempt is
// over (enforcement, read after the apply — never the value the caller sent).
func (s *Server) writeApplied(ctx context.Context, w http.ResponseWriter, actor string,
	applied settings.ApplyResult, extra map[string]any) {

	state := s.enforcementNow()
	want := s.deps.Settings.Current().Enforcement
	inEffect := applied.OK() && enforcementHolds(want, state)

	// An empty list rather than null: "nothing was refused" is a fact worth
	// stating plainly, and a client counting the entries should not have to
	// guard against a missing array to learn it.
	errs := applied.Errors
	if errs == nil {
		errs = []settings.ApplyError{}
	}
	body := map[string]any{
		"ok":     inEffect,
		"stored": true,
		"applied": map[string]any{
			"ok":     applied.OK(),
			"errors": errs,
		},
	}
	for k, v := range extra {
		body[k] = v
	}
	if state != nil {
		body["enforcement"] = state
	}
	if inEffect {
		writeJSON(w, http.StatusOK, body)
		return
	}
	// A refusal that only reaches the caller leaves no trace of the window in
	// which the operator believed they were protected.
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: actor, Action: "settings_apply_failed", Detail: applyDetail(applied, want, state),
	})
	writeJSON(w, http.StatusAccepted, body)
}

// enforcementNow reads the firewall's own verdict. Nil when there is no
// firewall to ask, and the key is then omitted rather than filled in: an
// absent answer is the honest one, and a manufactured state here would be the
// defect this endpoint was fixed for, one layer down.
func (s *Server) enforcementNow() *firewall.EnforcementState {
	if s.deps.Firewall == nil {
		return nil
	}
	st := s.deps.Firewall.State()
	return &st
}

// enforcementHolds reports whether the firewall ended up where the settings
// point, judged on the read-back rather than on the request.
//
// Unverified counts as holding. It means the writes went in and nobody has
// read the kernel back yet — true for the first two minutes of every process
// and after every arm — which is an absence of evidence, not evidence of
// refusal. Answering 202 there would call a change that did take "not in
// effect", which is the same class of untruth pointed the other way. The
// verdict travels in the body either way, and it is the verdict, not the
// status code, that decides whether a screen may go green.
func enforcementHolds(want string, st *firewall.EnforcementState) bool {
	if st == nil {
		return true
	}
	// SetEnforce leaves the mode where it actually ended up, so a mismatch
	// here means the switch was refused before it flipped.
	if st.Mode != want {
		return false
	}
	switch st.Verdict {
	case firewall.VerdictUnable, firewall.VerdictDegraded:
		return false
	default:
		return true
	}
}

// applyDetail renders the reason for the audit row, preferring what the
// subsystems said over what the state implies, because the subsystem knows the
// cause and the state only knows the symptom.
func applyDetail(applied settings.ApplyResult, want string, st *firewall.EnforcementState) string {
	if !applied.OK() {
		parts := make([]string, 0, len(applied.Errors))
		for _, e := range applied.Errors {
			parts = append(parts, e.Field+": "+e.Message)
		}
		return strings.Join(parts, "; ")
	}
	if st == nil {
		return "enforcement=" + want + " could not be confirmed"
	}
	return "enforcement=" + want + " but the firewall is " + string(st.Verdict)
}
