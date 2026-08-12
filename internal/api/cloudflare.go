package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/cloudflare"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// CloudflareService is the Cloudflare integration the API drives. The concrete
// *cloudflare.Manager satisfies it; the interface keeps the handlers testable
// and the token-handling out of the HTTP layer.
type CloudflareService interface {
	Status(ctx context.Context) (cloudflare.Status, error)
	Connect(ctx context.Context, token string) (cloudflare.Status, error)
	Disconnect(ctx context.Context) error
	SetMonitored(ctx context.Context, zoneID string, on bool) error
	Analytics(ctx context.Context, zoneID string, window time.Duration) (cloudflare.AnalyticsSeries, error)
}

const maxAnalyticsWindow = 720 * time.Hour // Cloudflare's 1h-groups limit

func (s *Server) handleCFStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cloudflare == nil {
		writeJSON(w, http.StatusOK, cloudflare.Status{Zones: []cloudflare.ZoneView{}})
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	st, err := s.deps.Cloudflare.Status(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleCFConnect(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cloudflare == nil {
		writeError(w, http.StatusNotImplemented, "cloudflare integration unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	st, err := s.deps.Cloudflare.Connect(ctx, req.Token)
	if err != nil {
		// A rejected or unscoped token is a client-side problem; report the
		// upstream message so the UI can tell the operator what to fix.
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "cloudflare_connect", Target: st.TokenID,
		Detail: pluralZones(len(st.Zones)),
	})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleCFDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cloudflare == nil {
		writeError(w, http.StatusNotImplemented, "cloudflare integration unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.deps.Cloudflare.Disconnect(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{Actor: id.name, Action: "cloudflare_disconnect"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCFSetZone(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cloudflare == nil {
		writeError(w, http.StatusNotImplemented, "cloudflare integration unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	zoneID := strings.TrimSpace(r.PathValue("id"))
	if zoneID == "" {
		writeError(w, http.StatusBadRequest, "missing zone id")
		return
	}
	var req struct {
		Monitored bool `json:"monitored"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch err := s.deps.Cloudflare.SetMonitored(ctx, zoneID, req.Monitored); {
	case errors.Is(err, store.ErrZoneNotFound):
		writeError(w, http.StatusNotFound, "unknown zone")
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "monitored": req.Monitored})
	}
}

func (s *Server) handleCFAnalytics(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cloudflare == nil {
		writeError(w, http.StatusNotImplemented, "cloudflare integration unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	zone := strings.TrimSpace(r.URL.Query().Get("zone"))
	if zone == "" {
		writeError(w, http.StatusBadRequest, "zone is required")
		return
	}
	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		d, err := config.ParseDuration(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid window: "+err.Error())
			return
		}
		window = d.Std()
	}
	if window > maxAnalyticsWindow {
		window = maxAnalyticsWindow
	}
	series, err := s.deps.Cloudflare.Analytics(ctx, zone, window)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, series)
}

func pluralZones(n int) string {
	if n == 1 {
		return "1 zone"
	}
	return itoa(n) + " zones"
}
