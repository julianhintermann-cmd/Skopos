package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/ai"
	"github.com/julianhintermann-cmd/skopos/internal/model"
)

// AIService is the AI integration the API drives. Note what the interface does
// not have: any method that returns a key. The HTTP layer has no way to ask for
// one, which is a stronger guarantee than remembering not to.
type AIService interface {
	Status() (ai.Status, error)
	Connect(ctx context.Context, p ai.Provider, key, model string) (ai.Status, error)
	Disconnect(ctx context.Context) error
	SetEnabled(enabled bool) (ai.Status, error)
	SetModel(model string) (ai.Status, error)
	Explain(ctx context.Context, system, user string, maxTokens int) (string, error)
}

// explainTokens bounds one answer. A paragraph, not an essay: the point is to
// turn a detector name into a sentence, and a longer budget mostly buys
// padding the operator has to read past at three in the morning.
const explainTokens = 400

// systemPrompt frames every request. It is deliberately explicit that the model
// is looking at redacted data and must not pretend otherwise — a confident
// guess about which device this is would be worse than no answer, because the
// operator cannot check it.
const systemPrompt = `You explain home-network security findings to a competent adult who is not a network engineer.

The data you are given is deliberately incomplete: addresses are reduced to a shape like 192.168.1.x, devices are numbered rather than named, and MAC addresses are never included. Do not ask for the missing parts and do not guess them.

Answer in at most three short paragraphs, in plain prose, no lists and no headings. Say what the finding means, what would ordinarily cause it, and what — if anything — is worth doing. If the evidence does not support a conclusion, say that plainly rather than offering a confident guess. You are one opinion beside the measurements, not a verdict on them.`

func (s *Server) aiUnavailable(w http.ResponseWriter) bool {
	if s.deps.AI == nil {
		writeError(w, http.StatusNotImplemented, "ai integration unavailable")
		return true
	}
	return false
}

func (s *Server) handleAIStatus(w http.ResponseWriter, _ *http.Request) {
	if s.deps.AI == nil {
		// Not an error: an install without the integration wired should render
		// the settings card and its provider list, not a failure.
		writeJSON(w, http.StatusOK, ai.Status{Providers: ai.Catalog()})
		return
	}
	st, err := s.deps.AI.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAIConnect(w http.ResponseWriter, r *http.Request) {
	if s.aiUnavailable(w) {
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	var req struct {
		Provider string `json:"provider"`
		Key      string `json:"key"`
		Model    string `json:"model"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := ai.Provider(strings.TrimSpace(req.Provider))
	if !p.Valid() {
		writeError(w, http.StatusBadRequest, "pick a provider first")
		return
	}
	if strings.TrimSpace(req.Key) == "" {
		writeError(w, http.StatusBadRequest, "an API key is required")
		return
	}

	st, err := s.deps.AI.Connect(ctx, p, req.Key, strings.TrimSpace(req.Model))
	if err != nil {
		writeError(w, aiStatusCode(err), err.Error())
		return
	}
	id, _ := identityFrom(r)
	// The key itself is never in the audit line — the provider and the last
	// four characters are enough to answer "which key was installed, and when".
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "ai_connect", Target: string(p),
		Detail: "key ending " + st.KeyTail + ", model " + st.Model,
	})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAIDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.aiUnavailable(w) {
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.deps.AI.Disconnect(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "ai_disconnect"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAISettings changes the model or the master switch without re-entering
// the key.
func (s *Server) handleAISettings(w http.ResponseWriter, r *http.Request) {
	if s.aiUnavailable(w) {
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	var req struct {
		Enabled *bool   `json:"enabled"`
		Model   *string `json:"model"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var st ai.Status
	var err error
	id, _ := identityFrom(r)
	if req.Model != nil {
		if st, err = s.deps.AI.SetModel(*req.Model); err != nil {
			writeError(w, aiStatusCode(err), err.Error())
			return
		}
		_ = s.deps.Store.Audit(ctx, model.AuditEntry{
			Actor: id.name, Action: "ai_model_change", Detail: st.Model,
		})
	}
	if req.Enabled != nil {
		if st, err = s.deps.AI.SetEnabled(*req.Enabled); err != nil {
			writeError(w, aiStatusCode(err), err.Error())
			return
		}
		// Turning it on is the moment household data becomes able to leave the
		// machine, so it is the moment the audit log has to record.
		action := "ai_disabled"
		if *req.Enabled {
			action = "ai_enabled"
		}
		_ = s.deps.Store.Audit(ctx, model.AuditEntry{
			Actor: id.name, Action: action, Target: string(st.Provider),
		})
	}
	if req.Model == nil && req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "nothing to change")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleAIExplain turns one alert, or one episode, into one paragraph.
//
// It reads the subject from the store rather than taking the facts from the
// client, so what is sent upstream is decided here and cannot be widened by
// crafting a request.
//
// Both subjects exist because both pages exist. The alerts list opens episodes
// and an ntfy push opens a single alert, and a feature that only worked on one
// of them would be missing from wherever the operator happened to be.
func (s *Server) handleAIExplain(w http.ResponseWriter, r *http.Request) {
	if s.aiUnavailable(w) {
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	var req struct {
		AlertID    int64 `json:"alert_id"`
		IncidentID int64 `json:"incident_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch {
	case req.AlertID > 0 && req.IncidentID > 0:
		writeError(w, http.StatusBadRequest, "pass alert_id or incident_id, not both")
		return
	case req.AlertID <= 0 && req.IncidentID <= 0:
		writeError(w, http.StatusBadRequest, "alert_id or incident_id is required")
		return
	}

	var (
		instruction string
		facts       any
		target      string
		subject     string
		err         error
	)
	if req.IncidentID > 0 {
		instruction, facts, target, err = s.incidentFacts(ctx, req.IncidentID)
		subject = "incident " + strconv.FormatInt(req.IncidentID, 10)
	} else {
		instruction, facts, target, err = s.alertFacts(ctx, req.AlertID)
		subject = "alert " + strconv.FormatInt(req.AlertID, 10)
	}
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	prompt, err := factsPrompt(instruction, facts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	answer, err := s.deps.AI.Explain(ctx, systemPrompt, prompt, explainTokens)
	if err != nil {
		writeError(w, aiStatusCode(err), err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "ai_explain", Target: target, Detail: subject,
	})
	// The redacted payload goes back with the answer. The operator can see
	// exactly what left the machine, rather than being asked to trust a
	// sentence in the settings page saying what would leave it.
	writeJSON(w, http.StatusOK, map[string]any{"answer": answer, "sent": facts})
}

// alertFacts loads one alert and reduces it to the safe set.
func (s *Server) alertFacts(ctx context.Context, id int64) (string, any, string, error) {
	a, err := s.deps.Store.Alert(ctx, id)
	if err != nil {
		return "", nil, "", errors.New("no such alert")
	}
	return "Explain this alert.", ai.ScrubAlert(a.Detector, string(a.Severity), a.Detail,
		s.country(a.Source), a.Source, 0, a.Count), a.Detector, nil
}

// incidentFacts loads one episode and reduces it to the safe set.
func (s *Server) incidentFacts(ctx context.Context, id int64) (string, any, string, error) {
	inc, err := s.deps.Store.IncidentByID(ctx, id)
	if err != nil {
		return "", nil, "", errors.New("no such incident")
	}
	src, _ := netip.ParseAddr(inc.Source)
	details := make([]string, 0, len(inc.Alerts))
	for _, a := range inc.Alerts {
		details = append(details, a.Detail)
	}
	target := ""
	if len(inc.Detectors) > 0 {
		target = inc.Detectors[0]
	}
	facts := ai.ScrubIncident(inc.Detectors, inc.Severity, s.country(src), src,
		inc.AlertCount, inc.Last.Sub(inc.First), details)
	return "Explain this episode — the same source firing repeatedly.", facts, target, nil
}

// country resolves an address to an ISO code, or to "" when GeoIP is absent or
// has no answer. An empty string is omitted from the payload rather than being
// sent as a guess.
func (s *Server) country(a netip.Addr) string {
	if s.deps.GeoIP == nil {
		return ""
	}
	if c, ok := s.deps.GeoIP.Lookup(a); ok {
		return c
	}
	return ""
}

// aiStatusCode maps a provider failure onto an HTTP status. The distinctions
// matter to the operator: a rejected key is something they fix, a rate limit is
// something they wait out, and a provider outage is neither.
func aiStatusCode(err error) int {
	switch {
	case errors.Is(err, ai.ErrNotConfigured):
		return http.StatusConflict
	case errors.Is(err, ai.ErrBadKey), errors.Is(err, ai.ErrNoCredit):
		return http.StatusBadRequest
	case errors.Is(err, ai.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ai.ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ai.ErrProviderDown):
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}

// factsPrompt renders the sanitised facts as the user turn. The facts go over
// as JSON rather than as an English sentence so the shape is fixed: a prompt
// assembled by string concatenation is a prompt whose contents drift the next
// time somebody edits it, and this is the one payload where that matters.
func factsPrompt(instruction string, facts any) (string, error) {
	body, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	prompt := instruction + "\n\n" + string(body)
	if err := ai.Clean(prompt); err != nil {
		return "", err
	}
	return prompt, nil
}
