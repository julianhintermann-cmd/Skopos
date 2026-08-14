package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// handleDeviceDetail assembles everything the device page shows in one round
// trip: the inventory record plus its traffic series, destinations and ports
// over the requested trailing window (default 24h). Traffic is keyed by the
// device's current IP — the pragmatic reading of a DHCP network.
func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	device, err := s.deps.Store.DeviceByMAC(ctx, mac)
	switch {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
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
	to := s.clock()
	from := to.Add(-window)
	res := store.ChooseResolution(window)

	ip := device.PrimaryAddr().String()

	// Five queries whose errors used to be dropped on the floor, so a database
	// that could not answer produced a page of confident empties: no
	// destinations, no ports, a flat chart. A key the server could not answer
	// is left out and named, which a view can render as "not available" —
	// nothing here may look like a finding of zero.
	payload := map[string]any{
		"device":     device,
		"from":       from,
		"to":         to,
		"resolution": res,
	}
	var missing unavailable

	if series, err := s.deps.Store.DeviceThroughput(ctx, ip, from, to, res); err == nil {
		payload["series"] = series.Points
		payload["bucket_seconds"] = series.BucketSeconds
		payload["coverage"] = series.Coverage
	} else {
		missing.add("series")
	}
	if destinations, err := s.deps.Store.DeviceDestinations(ctx, ip, from, to, res, 15); err == nil {
		payload["destinations"] = destinations
	} else {
		missing.add("destinations")
	}
	if ports, err := s.deps.Store.DevicePorts(ctx, ip, from, to, res, 12); err == nil {
		payload["ports"] = ports
	} else {
		missing.add("ports")
	}
	// Passive DNS and TLS: what this device actually asked for, and which
	// client software asked.
	if domains, err := s.deps.Store.TopDomains(ctx, from, to, ip, 15); err == nil {
		payload["domains"] = domains
	} else {
		missing.add("domains")
	}
	if fingerprints, err := s.deps.Store.DeviceFingerprints(ctx, ip, 8); err == nil {
		payload["fingerprints"] = fingerprints
	} else {
		missing.add("fingerprints")
	}
	if len(missing) > 0 {
		payload["unavailable"] = []string(missing)
	}
	writeJSON(w, http.StatusOK, payload)
}
