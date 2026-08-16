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
	// Enforcement is what the kernel was last found to hold. It is added
	// alongside Enforcing rather than replacing it, and it deliberately does
	// not feed OK.
	//
	// OK drives the container healthcheck, and a 503 there restarts the
	// container. EnsureBase commits its teardown separately from its rebuild,
	// so every restart widens the window in which the table does not exist —
	// a failing kernel check that forced restarts would leave the firewall off
	// for longer than the failure it was reacting to, in a loop. The check
	// reports; the repair is reapplyAll's job, and it already runs.
	Enforcement *firewall.EnforcementState `json:"enforcement,omitempty"`
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

// unavailable collects the keys a response could not answer. A field carrying
// a measurement must not be present unless it was measured, so a failed query
// omits its key and names it here instead of filling in a zero — "Unacked
// alerts 0", in green, was what an unreachable database used to look like.
type unavailable []string

func (u *unavailable) add(key string) { *u = append(*u, key) }

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	now := s.clock()
	from := now.Add(-time.Hour)
	// One constant, used for the query and reported to the client, so the two
	// cannot drift apart — the chart divides by it to get a rate.
	res := store.Res1m

	var missing unavailable
	payload := map[string]any{
		"live":       s.liveSnapshot(),
		"resolution": res,
		// enforcing is the configuration's intention and stays for older
		// clients. enforcement is what the kernel was last found to hold, and
		// is what a view should render — the two disagree exactly when it
		// matters, and only the second one can say "unconfirmed since 09:14".
		"enforcing":   s.deps.Firewall.Enforcing(),
		"enforcement": s.deps.Firewall.State(),
	}
	if series, err := s.deps.Store.Throughput(ctx, from, now, res); err == nil {
		// bucket_seconds ships alongside the resolution: the chart turns bucket
		// totals into a rate and should not have to re-derive how long a bucket
		// is, nor decline to draw a resolution it does not recognise.
		payload["bucket_seconds"] = series.BucketSeconds
		payload["throughput_1h"] = series.Points
		payload["coverage"] = series.Coverage
	} else {
		missing.add("throughput_1h")
	}
	if talkers, err := s.deps.Store.TopTalkers(ctx, from, now, res, 10); err == nil {
		payload["top_talkers"] = talkers
	} else {
		missing.add("top_talkers")
	}
	if blocks, err := s.deps.Store.ActiveBlocks(ctx); err == nil {
		payload["active_blocks"] = len(blocks)
	} else {
		missing.add("active_blocks")
	}
	if unacked, err := s.deps.Store.CountUnackedAlerts(ctx); err == nil {
		payload["unacked_alerts"] = unacked
	} else {
		missing.add("unacked_alerts")
	}
	if len(missing) > 0 {
		payload["unavailable"] = []string(missing)
	}
	writeJSON(w, http.StatusOK, payload)
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
		// Clamped, not taken as given: a finer resolution over a wide span is
		// a denial of service anyone can send at an unauthenticated port.
		res = store.ClampResolution(store.Resolution(v), to.Sub(from))
	}
	series, err := s.deps.Store.Throughput(ctx, from, to, res)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var missing unavailable
	payload := map[string]any{
		"from": from, "to": to, "resolution": res,
		"bucket_seconds": series.BucketSeconds,
		"series":         series.Points,
		"coverage":       series.Coverage,
	}
	if talkers, err := s.deps.Store.TopTalkers(ctx, from, to, res, 25); err == nil {
		payload["top_talkers"] = talkers
	} else {
		missing.add("top_talkers")
	}
	if len(missing) > 0 {
		payload["unavailable"] = []string(missing)
	}
	writeJSON(w, http.StatusOK, payload)
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
		// What the kernel was last actually found to hold, so the view can say
		// "unconfirmed since 09:14" instead of painting every row green on the
		// strength of a configuration file.
		"kernel": s.deps.Firewall.State(),
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
		// Deliberately says what it refuses, not what it guarantees: two
		// halves of the address space blocked separately add up to the same
		// thing, and neither half trips this. Promising an invariant that a
		// second click defeats would be its own small untruth.
		writeError(w, http.StatusBadRequest,
			"refusing to block "+prefix.String()+": a whole address family at once would "+
				"include the address you are reading this from. Block a narrower range.")
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
	switch {
	case errors.Is(err, firewall.ErrStillBlocked):
		// The raw netlink wording never reaches the operator, and the sentence
		// they do get has to be true: the block really is still in place.
		s.log("unblocking %s failed: %v", prefix, err)
		writeError(w, http.StatusConflict,
			"could not unblock "+prefix.String()+": the firewall rejected the change, "+
				"so the block is still in place. The details are in the Skopos log.")
		return
	case err != nil:
		s.log("unblocking %s failed: %v", prefix, err)
		writeError(w, http.StatusInternalServerError,
			"could not unblock "+prefix.String()+". The details are in the Skopos log.")
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

// handleAudit serves the audit log, filtered by actor, action, target and time
// window, one page at a time.
//
// Everything but limit is new. The endpoint could only hand back the newest
// entries under a limit, so past one screenful "who blocked this, and when"
// had no answer — in the one record whose entire value is that it says what
// happened.
//
// A malformed parameter is refused here rather than ignored as the flow
// endpoints ignore a bad `from`. There a dropped parameter costs a wider
// chart; here it answers a different question from the one that was asked
// while looking exactly like the right answer. An operator narrowing to one
// address would be shown the whole log, and a cursor that failed to parse
// would hand them the newest entries labelled as the continuation of the page
// they were reading.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()

	q := r.URL.Query()
	f := store.AuditFilter{
		Actor:  strings.TrimSpace(q.Get("actor")),
		Action: strings.TrimSpace(q.Get("action")),
		Target: strings.TrimSpace(q.Get("target")),
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit: "+v)
			return
		}
		f.Limit = n
	}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid from: expected an RFC3339 time, got "+v)
			return
		}
		f.Since = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid to: expected an RFC3339 time, got "+v)
			return
		}
		f.Until = t
	}
	if v := q.Get("cursor"); v != "" {
		c, err := store.ParseAuditCursor(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		f.Before = c
	}

	page, err := s.deps.Store.ListAuditPage(ctx, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// next_cursor is always present, empty when this page reaches the end of
	// the log: "there is no more" is a fact worth stating, and a client should
	// not have to infer it from a missing field.
	writeJSON(w, http.StatusOK, map[string]any{
		"audit":       page.Entries,
		"next_cursor": page.Next.String(),
	})
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

// handleAlert returns one alert by id.
//
// The detail page previously found its alert by pulling the 500 most recent
// and searching them, so an alert older than that rendered as "not in the
// current list" while its row sat in the table — on the page a three-in-the-
// morning ntfy push lands on.
func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	alert, err := s.deps.Store.Alert(ctx, id)
	if errors.Is(err, store.ErrAlertNotFound) {
		writeError(w, http.StatusNotFound, "no such alert")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alert)
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
	// operator sees the effect immediately — and say which of the two things
	// happened. The policy is stored either way; whether it is in force is a
	// separate fact, and answering 200 for both meant a quarantined device
	// showed as restricted while it still reached the internet.
	if s.deps.ApplyDevicePolicies != nil {
		if err := s.deps.ApplyDevicePolicies(); err != nil {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"ok": false, "stored": true, "policy": policy,
				"applied": map[string]any{"ok": false, "error": err.Error()},
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "stored": true, "policy": policy,
		"applied": map[string]any{"ok": true},
	})
}
