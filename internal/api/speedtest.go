package api

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) handleSpeedtestHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	results, err := s.deps.Store.ListSpeedtests(ctx, 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleSpeedtestRun triggers a measurement on demand. A real test moves tens
// of megabytes, so this deliberately runs synchronously with a generous
// timeout — the UI shows a progress state meanwhile.
func (s *Server) handleSpeedtestRun(w http.ResponseWriter, r *http.Request) {
	if s.deps.Speedtest == nil {
		writeError(w, http.StatusNotImplemented, "speedtest unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	res, err := s.deps.Speedtest(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
