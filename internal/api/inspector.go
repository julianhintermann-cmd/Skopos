package api

import "net/http"

// The kernel inspector. Every other firewall surface in Skopos answers from the
// database's intention — the block list, the counts, the pill in the header.
// This one asks the kernel and reports what came back, including the answer
// nobody wants to see.
//
// GET /api/firewall/kernel, read scope, no side effects. It is on demand: one
// call reads every set, so nothing should poll it (the backend refuses to
// re-read the kernel more than twice a minute and replays its last snapshot,
// which read_at dates honestly).
func (s *Server) handleKernelDump(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	snapshot, err := s.deps.Firewall.Dump(ctx)
	if err != nil {
		// 503 with no snapshot key at all. An empty object here would render
		// as a table that is gone and fourteen sets holding nothing — the most
		// alarming thing this endpoint can say, and the one thing it must
		// never say without having read it. "Could not read the kernel" and
		// "the kernel holds nothing" are different answers, and the whole
		// point of this endpoint is that it can tell them apart.
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":       err.Error(),
			"enforcement": s.deps.Firewall.State(),
		})
		return
	}

	payload := map[string]any{
		"snapshot":    snapshot,
		"enforcement": s.deps.Firewall.State(),
	}
	// intent is what Skopos believes it put in each set, so the view can put
	// the two columns side by side. Absent is not empty: without it every set
	// looks agreed-upon, and an empty set that ought to hold something is
	// exactly the disagreement this endpoint was built to surface.
	var missing unavailable
	if intent, err := s.deps.Firewall.Intent(ctx); err == nil {
		payload["intent"] = intent
	} else {
		missing.add("intent")
	}
	if len(missing) > 0 {
		payload["unavailable"] = []string(missing)
	}
	writeJSON(w, http.StatusOK, payload)
}
