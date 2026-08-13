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
	series, _ := s.deps.Store.DeviceThroughput(ctx, ip, from, to, res)
	destinations, _ := s.deps.Store.DeviceDestinations(ctx, ip, from, to, res, 15)
	ports, _ := s.deps.Store.DevicePorts(ctx, ip, from, to, res, 12)
	// Passive DNS and TLS: what this device actually asked for, and which
	// client software asked.
	domains, _ := s.deps.Store.TopDomains(ctx, from, to, ip, 15)
	fingerprints, _ := s.deps.Store.DeviceFingerprints(ctx, ip, 8)

	writeJSON(w, http.StatusOK, map[string]any{
		"device":       device,
		"from":         from,
		"to":           to,
		"resolution":   res,
		"series":       series,
		"destinations": destinations,
		"ports":        ports,
		"domains":      domains,
		"fingerprints": fingerprints,
	})
}
