package api

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/wol"
)

// beginCSV sets download headers and returns a CSV writer for the response.
// The filename carries the current date so repeated exports do not collide in
// a download folder.
func beginCSV(w http.ResponseWriter, name string, now time.Time) *csv.Writer {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="skopos-%s-%s.csv"`, name, now.Format("20060102-1504")))
	return csv.NewWriter(w)
}

func (s *Server) handleExportFlows(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	to := s.clock()
	from := to.Add(-24 * time.Hour)
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	limit := 50000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200000 {
			limit = n
		}
	}

	flows, err := s.deps.Store.ExportFlows(ctx, from, to, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cw := beginCSV(w, "flows", s.clock())
	_ = cw.Write([]string{"start", "end", "src_ip", "src_port", "dst_ip", "dst_port",
		"proto", "direction", "out_bytes", "out_packets", "in_bytes", "in_packets", "dst_name"})
	for _, f := range flows {
		_ = cw.Write([]string{
			f.Start.UTC().Format(time.RFC3339), f.End.UTC().Format(time.RFC3339),
			f.SrcIP.String(), strconv.Itoa(int(f.SrcPort)),
			f.DstIP.String(), strconv.Itoa(int(f.DstPort)),
			f.Proto.String(), string(f.Dir),
			strconv.FormatUint(f.OutBytes, 10), strconv.FormatUint(f.OutPackets, 10),
			strconv.FormatUint(f.InBytes, 10), strconv.FormatUint(f.InPackets, 10),
			f.DstName,
		})
	}
	cw.Flush()
}

func (s *Server) handleExportDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	devices, err := s.deps.Store.ListDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cw := beginCSV(w, "devices", s.clock())
	_ = cw.Write([]string{"name", "label", "hostname", "ip", "mac", "vendor", "first_seen", "last_seen"})
	for _, d := range devices {
		_ = cw.Write([]string{
			d.Name(), d.Label, d.Hostname, d.IP.String(), d.MAC, d.Vendor,
			d.FirstSeen.UTC().Format(time.RFC3339), d.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
}

func (s *Server) handleExportAlerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	alerts, err := s.deps.Store.ListAlerts(ctx, store.AlertFilter{Limit: 10000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cw := beginCSV(w, "alerts", s.clock())
	_ = cw.Write([]string{"id", "time", "detector", "severity", "source", "title", "detail", "count", "acknowledged"})
	for _, a := range alerts {
		src := ""
		if a.Source.IsValid() {
			src = a.Source.String()
		}
		_ = cw.Write([]string{
			strconv.FormatInt(a.ID, 10), a.Time.UTC().Format(time.RFC3339),
			a.Detector, string(a.Severity), src, a.Title, a.Detail,
			strconv.Itoa(a.Count), strconv.FormatBool(a.Ack),
		})
	}
	cw.Flush()
}

// handleWakeDevice broadcasts a Wake-on-LAN magic packet for the MAC. The
// device does not need to be in the inventory — a magic packet is a harmless
// broadcast — but the MAC must parse.
func (s *Server) handleWakeDevice(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := r.PathValue("mac")
	if _, err := net.ParseMAC(mac); err != nil {
		writeError(w, http.StatusBadRequest, "invalid mac address")
		return
	}
	wake := s.deps.WakeFunc
	if wake == nil {
		wake = wol.Wake
	}
	if err := wake(mac); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_wake", Target: mac,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mac": mac})
}
