package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/julianhintermann-cmd/skopos/internal/blockwatch"
	"github.com/julianhintermann-cmd/skopos/internal/config"
	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/model"
	"github.com/julianhintermann-cmd/skopos/internal/store"
	"github.com/julianhintermann-cmd/skopos/internal/updatecheck"
	"github.com/julianhintermann-cmd/skopos/internal/version"
)

// Health is the /api/health payload.
type Health struct {
	OK        bool   `json:"ok"`
	Version   string `json:"version"`
	Capture   string `json:"capture"`
	Firewall  string `json:"firewall"`
	Enforcing bool   `json:"enforcing"`
	ColdOK    bool   `json:"cold_storage_ok"`
	// Mirror is true when at least one capture interface is declared as a
	// mirror/SPAN port: Skopos then sees the whole segment, while blocking
	// still acts only on traffic passing this machine.
	Mirror bool   `json:"mirror"`
	Detail string `json:"detail,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	h := Health{OK: true}
	if s.deps.Health != nil {
		h = s.deps.Health()
	}
	status := http.StatusOK
	if !h.OK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, h)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	now := s.clock()
	from := now.Add(-time.Hour)
	// One constant, used for the query and reported to the client, so the two
	// cannot drift apart — the chart divides by it to get a rate.
	res := store.Res1m
	series, _ := s.deps.Store.Throughput(ctx, from, now, res)
	talkers, _ := s.deps.Store.TopTalkers(ctx, from, now, res, 10)
	blocks, _ := s.deps.Store.ActiveBlocks(ctx)
	unacked, _ := s.deps.Store.CountUnackedAlerts(ctx)

	writeJSON(w, http.StatusOK, map[string]any{
		"live": s.liveSnapshot(),
		// The chart turns bucket totals into a rate, so it needs to know how
		// long a bucket is rather than assuming.
		"resolution":     res,
		"throughput_1h":  series,
		"top_talkers":    talkers,
		"active_blocks":  len(blocks),
		"unacked_alerts": unacked,
		"enforcing":      s.deps.Firewall.Enforcing(),
	})
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	q := r.URL.Query()
	to := s.clock()
	from := to.Add(-time.Hour)
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
	res := store.ChooseResolution(to.Sub(from))
	if v := q.Get("resolution"); v != "" {
		res = store.Resolution(v)
	}
	series, err := s.deps.Store.Throughput(ctx, from, to, res)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	talkers, _ := s.deps.Store.TopTalkers(ctx, from, to, res, 25)
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "resolution": res,
		"series": series, "top_talkers": talkers,
	})
}

// handleLiveFlows returns the most recently completed flows so the live view
// starts populated; subsequent updates arrive over the SSE stream.
func (s *Server) handleLiveFlows(w http.ResponseWriter, r *http.Request) {
	var flows []LiveFlow
	if s.deps.LiveFlows != nil {
		flows = s.deps.LiveFlows.RecentFlows()
	}
	if flows == nil {
		flows = []LiveFlow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"flows": flows})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	devices, err := s.deps.Store.ListDevices(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// forgetLimit bounds one cleanup request. Well above any real inventory, low
// enough that a stray call cannot walk the whole table.
const forgetLimit = 1000

// handleForgetDevices drops inventory entries the operator does not recognise
// as devices. Discovery is passive and continuous, so this is not a deletion
// in the usual sense: a machine that is still on the network reappears with
// its next packet. What it does clear for good is the residue — entries left
// by traffic that never had a device behind it.
func (s *Server) handleForgetDevices(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	var req struct {
		MACs []string `json:"macs"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	macs := make([]string, 0, len(req.MACs))
	for _, m := range req.MACs {
		if m = strings.TrimSpace(m); m != "" {
			macs = append(macs, m)
		}
	}
	if len(macs) == 0 {
		writeError(w, http.StatusBadRequest, "no devices given")
		return
	}
	if len(macs) > forgetLimit {
		writeError(w, http.StatusBadRequest, "too many devices in one request")
		return
	}

	removed, err := s.deps.Store.ForgetDevices(ctx, macs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	id, _ := identityFrom(r)
	target := macs[0]
	detail := "forgot inventory entry"
	if len(macs) > 1 {
		target = fmt.Sprintf("%d entries", len(macs))
		detail = "forgot " + strings.Join(macs, ", ")
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_forget", Target: target, Detail: detail,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

// handleSetDeviceLabel assigns an operator-chosen name to a device. An empty
// label clears it, falling back to the discovered hostname.
func (s *Server) handleSetDeviceLabel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	if mac == "" {
		writeError(w, http.StatusBadRequest, "missing device mac")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > 64 {
		writeError(w, http.StatusBadRequest, "label too long (max 64 characters)")
		return
	}

	switch err := s.deps.Store.SetDeviceLabel(ctx, mac, label); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	id, _ := identityFrom(r)
	detail := "cleared label"
	if label != "" {
		detail = "renamed to " + label
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_label", Target: mac, Detail: detail,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mac": mac, "label": label})
}

// handleSetDevicePresence toggles arrive/leave notifications for a device.
func (s *Server) handleSetDevicePresence(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	var req struct {
		Watch bool `json:"watch"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Seeding uses the same threshold the tracker applies, so a device that is
	// currently online starts as present without firing a notification.
	switch err := s.deps.Store.SetDeviceWatchPresence(ctx, mac, req.Watch, 10*time.Minute); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	detail := "presence tracking off"
	if req.Watch {
		detail = "presence tracking on"
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_presence", Target: mac, Detail: detail,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "watch": req.Watch})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	filter := store.AlertFilter{}
	if r.URL.Query().Get("unacked") == "true" {
		filter.UnackedOnly = true
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	alerts, err := s.deps.Store.ListAlerts(ctx, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	if err := s.deps.Store.AckAlert(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// blockRow is a block plus its observed attempt tally. The capture tap sees
// packets before netfilter drops them, so attempts keep counting while a
// block works — that is the proof it works, not a sign it doesn't.
type blockRow struct {
	model.Block
	Attempts    uint64     `json:"attempts"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
}

func (s *Server) handleListBlocks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	blocks, err := s.deps.Store.ActiveBlocks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var stats map[string]blockwatch.Stat
	if s.deps.BlockStats != nil {
		stats = s.deps.BlockStats()
	}
	rows := make([]blockRow, 0, len(blocks))
	for _, b := range blocks {
		row := blockRow{Block: b}
		if st, ok := stats[b.Prefix.String()]; ok {
			row.Attempts = st.Attempts
			if !st.Last.IsZero() {
				t := st.Last
				row.LastAttempt = &t
			}
		}
		rows = append(rows, row)
	}
	// Enforcement state rides along so the view qualifying these blocks is
	// atomic with them: "recorded" and "actually dropped" are different
	// claims, and the UI must never show the second while the first is true.
	// The never-block set rides along too, so a block form can say "this one
	// is protected" before the operator commits rather than after.
	protected := make([]string, 0, 4)
	for _, p := range s.deps.Firewall.ProtectedPrefixes() {
		protected = append(protected, p.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"blocks":      rows,
		"enforcement": s.deps.Config.Firewall.Enforcement,
		"enforcing":   s.deps.Firewall.Enforcing(),
		"protected":   protected,
	})
}

func (s *Server) handleAddBlock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	var req struct {
		Prefix string `json:"prefix"`
		Reason string `json:"reason"`
		TTL    string `json:"ttl"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	prefix, err := parsePrefixOrIP(req.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix: "+err.Error())
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := config.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid ttl: "+err.Error())
			return
		}
		ttl = d.Std()
	}
	id, _ := identityFrom(r)
	switch err := s.deps.Firewall.ManualBlock(ctx, prefix, id.name, req.Reason, ttl); {
	case errors.Is(err, firewall.ErrProtected):
		// Refusing is the whole point: this is one tap on a phone, and the
		// address it would take down is the one the operator needs to reach
		// the dashboard from. Removing it from the allowlist is the path.
		writeError(w, http.StatusBadRequest, err.Error()+
			" — remove it from the allowlist in Settings first if you really mean it")
		return
	case errors.Is(err, firewall.ErrWholeFamily):
		writeError(w, http.StatusBadRequest,
			"refusing to block "+prefix.String()+": that is every address at once, "+
				"including the one you are reading this from. Block a narrower range.")
		return
	case errors.Is(err, firewall.ErrNotEnforced):
		// The kernel's own wording ("file exists", "invalid argument") is not
		// something an operator should ever have to read, and worse, it used
		// to arrive next to a block that had already been written. Say plainly
		// that nothing happened, and keep the detail in the log.
		s.log("blocking %s failed: %v", prefix, err)
		writeError(w, http.StatusConflict,
			"could not block "+prefix.String()+": the firewall rejected the change, "+
				"so nothing was blocked and nothing was recorded. The details are in the Skopos log.")
		return
	case err != nil:
		s.log("blocking %s failed: %v", prefix, err)
		writeError(w, http.StatusInternalServerError,
			"could not block "+prefix.String()+". The details are in the Skopos log.")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"prefix": prefix.String()})
}

func (s *Server) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	prefix, err := parsePrefixOrIP(r.URL.Query().Get("prefix"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix: "+err.Error())
		return
	}
	id, _ := identityFrom(r)
	removed, err := s.deps.Firewall.Unblock(ctx, prefix, id.name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !removed {
		writeError(w, http.StatusNotFound, "no active block for that prefix")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	// Read-only view of the effective rule configuration (the YAML is the
	// source of truth; the UI never edits it).
	c := s.deps.Config
	writeJSON(w, http.StatusOK, map[string]any{
		"enforcement": c.Firewall.Enforcement,
		"detection":   c.Detection,
		"firewall":    c.Firewall,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := s.deps.Store.ListAudit(ctx, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(w, r, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := config.Parse(body); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.deps.Notifier.Test(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.hub.serveSSE(w, r, 25*time.Second)
}

// parsePrefixOrIP accepts either a CIDR or a bare IP (treated as a host /32 or
// /128).
// Unmapping matters: ::ffff:203.0.113.5 is an IPv4 address wearing an IPv6
// coat. Left alone it lands in the v6 set, whose rules only match nfproto
// ipv6, so a real IPv4 packet from that address never touches it — a block the
// UI lists as active and the kernel silently ignores.
func parsePrefixOrIP(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return netip.PrefixFrom(p.Addr().Unmap(), unmappedBits(p)).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmappedBits rebases a prefix length onto the unmapped address: a 4-in-6
// /128 is a /32 once the 96-bit prefix is gone.
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// handleUpdates reports whether a newer release exists. Disabled or
// not-yet-run checks answer honestly rather than claiming "up to date".
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if s.deps.Updates == nil {
		writeJSON(w, http.StatusOK, updatecheck.Status{Current: version.Version})
		return
	}
	writeJSON(w, http.StatusOK, s.deps.Updates())
}

// handleSetDevicePolicy confines a device: "lan_only" cuts it off from the
// internet, "quarantine" cuts it off entirely, empty lifts the restriction.
//
// Like every Skopos rule this acts in the kernel of the machine running
// Skopos, so it bites on traffic that machine sees or routes. On a NAS that
// is not the network's gateway, a device's own path to the internet runs
// through the router and stays out of reach — the UI says so plainly rather
// than implying a guarantee that is not there.
func (s *Server) handleSetDevicePolicy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	mac := strings.TrimSpace(r.PathValue("mac"))
	var req struct {
		Policy string `json:"policy"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	policy := model.DevicePolicy(strings.TrimSpace(req.Policy))
	if !policy.Valid() {
		writeError(w, http.StatusBadRequest, "policy must be empty, lan_only or quarantine")
		return
	}
	// Confining a device is a block by another name, and a stronger one: its
	// rules sit ahead of the conntrack exemption, so they cut connections
	// already in progress. The never-block list governs it exactly as it
	// governs an explicit block — the gateway most of all, since quarantining
	// it takes down the network the dashboard is reached over.
	if policy != model.PolicyOpen {
		device, err := s.deps.Store.DeviceByMAC(ctx, mac)
		if err == nil {
			for _, addr := range device.Addrs() {
				if p, ok := s.deps.Firewall.Protects(netip.PrefixFrom(addr, addr.BitLen())); ok {
					writeError(w, http.StatusBadRequest, fmt.Sprintf(
						"%s is on the never-block allowlist (%s) — remove it in Settings first if you really mean it",
						addr, p))
					return
				}
			}
		}
	}
	switch err := s.deps.Store.SetDevicePolicy(ctx, mac, policy); {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no device with that mac")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := identityFrom(r)
	detail := "policy cleared"
	if policy != model.PolicyOpen {
		detail = "policy " + string(policy)
	}
	_ = s.deps.Store.Audit(ctx, model.AuditEntry{
		Actor: id.name, Action: "device_policy", Target: mac, Detail: detail,
	})
	// Push it to the kernel now instead of waiting for the sync loop, so the
	// operator sees the effect immediately.
	if s.deps.ApplyDevicePolicies != nil {
		s.deps.ApplyDevicePolicies()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}
