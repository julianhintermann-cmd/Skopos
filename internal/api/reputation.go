package api

import (
	"net/http"
	"net/netip"
	"strings"
)

func (s *Server) handleReputation(w http.ResponseWriter, r *http.Request) {
	if s.deps.Reputation == nil {
		writeError(w, http.StatusNotImplemented, "reputation unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	info, err := s.deps.Reputation.Lookup(ctx, addr)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}
