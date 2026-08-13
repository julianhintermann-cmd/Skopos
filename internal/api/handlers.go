package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/blockwatch"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/updatecheck"
	"github.com/julianhintermann-cmd/skopos/internal/version"
)

// Health is the /api/health payload.
type Health struct {
	OK        bool   `json:"ok"`
	Version   string `json:"version"`
	Capture   string `json:"capture"`
	Firewall  string `json:"firewall"`
	Enforcing bool   `json:"enforcing"`
	ColdOK    bool   `json:"cold_storage_ok"`
	Detail    string `json:"detail,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	h := Health{OK: true}
	if s.deps.Health != nil {
		h = s.deps.Health()
	}
	status := http.StatusOK
	if !h.OK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, h)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	now := s.clock()
	from := now.Add(-time.Hour)
	series, _ := s.deps.Store.Throughput(ctx, from, now, store.Res1m)
	talkers, _ := s.deps.Store.TopTalkers(ctx, from, now, store.Res1m, 10)
	blocks, _ := s.deps.Store.ActiveBlocks(ctx)
	unacked, _ := s.deps.Store.CountUnackedAlerts(ctx)

	writeJSON(w, http.StatusOK, map[string]any{
		"live":           s.liveSnapshot(),
		"throughput_1h":  series,
		"top_talkers":    talkers,
		"active_blocks":  len(blocks),
		"unacked_alerts": unacked,
		"enforcing":      s.deps.Firewall.Enforcing(),
	})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	q := r.URL.Query()
	to := s.clock()
	from := to.Add(-time.Hour)
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	res := store.ChooseResolution(to.Sub(from))
	if v := q.Get("resolution"); v != "" {
		res = store.Resolution(v)
	}
	series, err := s.deps.Store.Throughput(ctx, from, to, res)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	talkers, _ := s.deps.Store.TopTalkers(ctx, from, to, res, 25)
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "resolution": res,
		"series": series, "top_talkers": talkers,
	})
}

// handleLiveFlows returns the most recently completed flows so the live view
// starts populated; subsequent updates arrive over the SSE stream.
func (s *Server) handleLiveFlows(w http.ResponseWriter, r *http.Request) {
	var flows []LiveFlow
	if s.deps.LiveFlows != nil {
		flows = s.deps.LiveFlows.RecentFlows()
	}
	if flows == nil {
		flows = []LiveFlow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	devices, err := s.deps.Store.ListDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// handleSetDeviceLabel assigns an operator-chosen name to a device. An empty
// label clears it, falling back to the discovered hostname.
func (s *Server) handleSetDeviceLabel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	if mac == "" {
		writeError(w, http.StatusBadRequest, "missing device mac")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > 64 {
		writeError(w, http.StatusBadRequest, "label too long (max 64 characters)")
		return
	}

	switch err := s.deps.Store.SetDeviceLabel(ctx, mac, label); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	id, _ := identityFrom(r)
	detail := "cleared label"
	if label != "" {
		detail = "renamed to " + label
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_label", Target: mac, Detail: detail,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mac": mac, "label": label})
}

// handleSetDevicePresence toggles arrive/leave notifications for a device.
func (s *Server) handleSetDevicePresence(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	var req struct {
		Watch bool `json:"watch"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Seeding uses the same threshold the tracker applies, so a device that is
	// currently online starts as present without firing a notification.
	switch err := s.deps.Store.SetDeviceWatchPresence(ctx, mac, req.Watch, 10*time.Minute); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	detail := "presence tracking off"
	if req.Watch {
		detail = "presence tracking on"
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_presence", Target: mac, Detail: detail,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "watch": req.Watch})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	filter := store.AlertFilter{}
	if r.URL.Query().Get("unacked") == "true" {
		filter.UnackedOnly = true
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	alerts, err := s.deps.Store.ListAlerts(ctx, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	if err := s.deps.Store.AckAlert(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// blockRow is a block plus its observed attempt tally. The capture tap sees
// packets before netfilter drops them, so attempts keep counting while a
// block works — that is the proof it works, not a sign it doesn't.
type blockRow struct {
	model.Block
	Attempts    uint64     `json:"attempts"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
}

func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	blocks, err := s.deps.Store.ActiveBlocks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var stats map[string]blockwatch.Stat
	if s.deps.BlockStats != nil {
		stats = s.deps.BlockStats()
	}
	rows := make([]blockRow, 0, len(blocks))
	for _, b := range blocks {
		row := blockRow{Block: b}
		if st, ok := stats[b.Prefix.String()]; ok {
			row.Attempts = st.Attempts
			if !st.Last.IsZero() {
				t := st.Last
				row.LastAttempt = &t
			}
		}
		rows = append(rows, row)
	}
	// Enforcement state rides along so the view qualifying these blocks is
	// atomic with them: "recorded" and "actually dropped" are different
	// claims, and the UI must never show the second while the first is true.
	writeJSON(w, http.StatusOK, map[string]any{
		"blocks":      rows,
		"enforcement": s.deps.Config.Firewall.Enforcement,
		"enforcing":   s.deps.Firewall.Enforcing(),
	})
}

func (s *Server) handleAddBlock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Prefix string `json:"prefix"`
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	prefix, err := parsePrefixOrIP(req.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix: "+err.Error())
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := config.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ttl: "+err.Error())
			return
		}
		ttl = d.Std()
	}
	id, _ := identityFrom(r)
	if err := s.deps.Firewall.ManualBlock(ctx, prefix, id.name, req.Reason, ttl); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"prefix": prefix.String()})
}

func (s *Server) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	prefix, err := parsePrefixOrIP(r.URL.Query().Get("prefix"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix: "+err.Error())
		return
	}
	id, _ := identityFrom(r)
	removed, err := s.deps.Firewall.Unblock(ctx, prefix, id.name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "no active block for that prefix")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	// Read-only view of the effective rule configuration (the YAML is the
	// source of truth; the UI never edits it).
	c := s.deps.Config
	writeJSON(w, http.StatusOK, map[string]any{
		"enforcement": c.Firewall.Enforcement,
		"detection":   c.Detection,
		"firewall":    c.Firewall,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := s.deps.Store.ListAudit(ctx, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := config.Parse(body); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.deps.Notifier.Test(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.hub.serveSSE(w, r, 25*time.Second)
}

// parsePrefixOrIP accepts either a CIDR or a bare IP (treated as a host /32 or
// /128).
func parsePrefixOrIP(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// handleUpdates reports whether a newer release exists. Disabled or
// not-yet-run checks answer honestly rather than claiming "up to date".
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if s.deps.Updates == nil {
		writeJSON(w, http.StatusOK, updatecheck.Status{Current: version.Version})
		return
	}
	writeJSON(w, http.StatusOK, s.deps.Updates())
}

// handleSetDevicePolicy confines a device: "lan_only" cuts it off from the
// internet, "quarantine" cuts it off entirely, empty lifts the restriction.
//
// Like every Skopos rule this acts in the kernel of the machine running
// Skopos, so it bites on traffic that machine sees or routes. On a NAS that
// is not the network's gateway, a device's own path to the internet runs
// through the router and stays out of reach — the UI says so plainly rather
// than implying a guarantee that is not there.
func (s *Server) handleSetDevicePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	var req struct {
		Policy string `json:"policy"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy := model.DevicePolicy(strings.TrimSpace(req.Policy))
	if !policy.Valid() {
		writeError(w, http.StatusBadRequest, "policy must be empty, lan_only or quarantine")
		return
	}
	switch err := s.deps.Store.SetDevicePolicy(ctx, mac, policy); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	detail := "policy cleared"
	if policy != model.PolicyOpen {
		detail = "policy " + string(policy)
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_policy", Target: mac, Detail: detail,
	})
	// Push it to the kernel now instead of waiting for the sync loop, so the
	// operator sees the effect immediately.
	if s.deps.ApplyDevicePolicies != nil {
		s.deps.ApplyDevicePolicies()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}
