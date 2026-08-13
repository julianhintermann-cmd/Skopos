package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// handleSearch answers "what actually happened at 3am": raw flows filtered by
// address, port, protocol, direction or destination name. The aggregated
// views cannot answer that — they have already thrown the detail away.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	q := r.URL.Query()
	to := s.clock()
	from := to.Add(-24 * time.Hour)
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
	if v := q.Get("window"); v != "" {
		if d, err := config.ParseDuration(v); err == nil {
			from = to.Add(-d.Std())
		}
	}

	f := store.SearchFilter{
		From:    from,
		To:      to,
		Address: strings.TrimSpace(q.Get("address")),
		Proto:   strings.TrimSpace(q.Get("proto")),
		Dir:     strings.TrimSpace(q.Get("dir")),
		Name:    strings.TrimSpace(q.Get("name")),
	}
	if v := q.Get("port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			writeError(w, http.StatusBadRequest, "invalid port")
			return
		}
		f.Port = n
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}

	flows, err := s.deps.Store.SearchFlows(ctx, f)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "count": len(flows),
		"flows": NewLiveFlows(flows, nil),
	})
}
