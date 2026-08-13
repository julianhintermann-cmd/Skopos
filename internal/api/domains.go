package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
)

// handleDomains aggregates which domains the network contacted over a window.
// Names come from passive DNS — the DNS and mDNS answers and TLS SNI Skopos
// observed on the wire — so this is what the devices actually asked for, not
// a reverse lookup guess.
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := config.ParseDuration(v); err == nil {
			window = d.Std()
		}
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	device := r.URL.Query().Get("device")

	to := s.clock()
	from := to.Add(-window)
	domains, err := s.deps.Store.TopDomains(ctx, from, to, device, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "device": device, "domains": domains,
	})
}
