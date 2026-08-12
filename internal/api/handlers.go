package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/store"
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

func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	blocks, err := s.deps.Store.ActiveBlocks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocks": blocks})
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
