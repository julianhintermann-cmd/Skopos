package api

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
)

// CountryStat is one country's share of a traffic direction.
type CountryStat struct {
	Country string `json:"country"`
	Bytes   int64  `json:"bytes"`
	Flows   int64  `json:"flows"`
}

// handleGeoIPSummary aggregates external traffic by country for the trailing
// window: outbound destinations ("where does my traffic go") and inbound
// sources ("who is knocking").
func (s *Server) handleGeoIPSummary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	if s.deps.GeoIP == nil || !s.deps.GeoIP.Available() {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false, "out": []CountryStat{}, "in": []CountryStat{},
			"blocked": s.blockedCountries(),
		})
		return
	}

	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := config.ParseDuration(v); err == nil {
			window = d.Std()
		}
	}
	to := s.clock()
	from := to.Add(-window)
	res := store.ChooseResolution(window)

	aggregate := func(dir string) []CountryStat {
		talkers, err := s.deps.Store.TopExternal(ctx, from, to, res, dir, 3000)
		if err != nil {
			return []CountryStat{}
		}
		byCountry := map[string]*CountryStat{}
		for _, t := range talkers {
			addr, err := netip.ParseAddr(t.Address)
			if err != nil {
				continue
			}
			code, ok := s.deps.GeoIP.Lookup(addr)
			if !ok {
				continue
			}
			cs := byCountry[code]
			if cs == nil {
				cs = &CountryStat{Country: code}
				byCountry[code] = cs
			}
			cs.Bytes += t.Bytes
			cs.Flows += t.Flows
		}
		out := make([]CountryStat, 0, len(byCountry))
		for _, cs := range byCountry {
			out = append(out, *cs)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
		if len(out) > 30 {
			out = out[:30]
		}
		return out
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"available": true,
		"from":      from, "to": to,
		"out":     aggregate("lan_wan"),
		"in":      aggregate("wan_lan"),
		"blocked": s.blockedCountries(),
	})
}

func (s *Server) blockedCountries() []string {
	if s.deps.Countries == nil {
		return []string{}
	}
	return s.deps.Countries.Countries()
}

// handleSetBlockedCountries replaces the blocked-country list. Blocking is
// reactive: sources from listed countries are blocked the moment they appear,
// once enforcement is on.
func (s *Server) handleSetBlockedCountries(w http.ResponseWriter, r *http.Request) {
	if s.deps.Countries == nil {
		writeError(w, http.StatusNotImplemented, "country blocking unavailable")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Countries []string `json:"countries"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Countries) > 100 {
		writeError(w, http.StatusBadRequest, "too many countries")
		return
	}
	if err := s.deps.Countries.Set(req.Countries); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "country_blocklist",
		Detail: strings.Join(s.deps.Countries.Countries(), ","),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "countries": s.deps.Countries.Countries()})
}
