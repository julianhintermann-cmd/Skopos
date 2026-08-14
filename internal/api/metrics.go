package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/julianhintermann-cmd/skopos/internal/firewall"
	"github.com/julianhintermann-cmd/skopos/internal/version"
)

// handleMetrics serves the Prometheus text exposition format. Hand-rolled
// rather than pulled from a client library: the exported set is small and
// static, and the image stays free of a dependency tree for nine gauges.
// The endpoint is behind the read scope like every other read — point your
// scraper at it with an API token (or none, in an `auth: none` LAN).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.deps.Config.Metrics.Enabled {
		writeError(w, http.StatusNotFound, "metrics endpoint is disabled (metrics.enabled)")
		return
	}
	ctx, cancel := reqCtx(r)
	defer cancel()

	var b strings.Builder
	metric := func(name, help, typ string, value float64, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s%s %g\n",
			name, help, name, typ, name, labelSet(labels), value)
	}

	metric("skopos_build_info", "Build information; always 1.", "gauge", 1, "version", version.Version)

	// Throughput gauges are absent from the scrape when the capture is not
	// running, so Prometheus renders a gap rather than a floor of zero that
	// looks exactly like a quiet network.
	live := s.liveSnapshot()
	if live.BitsPerSecond != nil {
		metric("skopos_throughput_bits_per_second", "Current observed throughput.", "gauge", *live.BitsPerSecond)
	}
	if live.PacketsPerSecond != nil {
		metric("skopos_throughput_packets_per_second", "Current observed packet rate.", "gauge", *live.PacketsPerSecond)
	}
	metric("skopos_capture_sampling", "1 when the capture is sampling to keep up.", "gauge", boolValue(live.Sampling))
	if live.KeepRate != nil {
		metric("skopos_capture_keep_rate", "Fraction of observed packets that survived sampling.", "gauge", *live.KeepRate)
	}
	if live.SourcesUp != nil && live.SourcesTotal != nil {
		metric("skopos_capture_sources_up", "Capture sources currently running.", "gauge", float64(*live.SourcesUp))
		metric("skopos_capture_sources_total", "Capture sources configured.", "gauge", float64(*live.SourcesTotal))
	}
	if live.Capture != "" {
		metric("skopos_capture_up", "1 when every configured capture source is running.", "gauge",
			boolValue(live.Capture == "up"))
	}
	if live.LastPacketAt != nil {
		metric("skopos_capture_last_packet_timestamp_seconds", "When a packet last arrived.", "gauge",
			float64(live.LastPacketAt.UnixNano())/1e9)
	}

	// Unchanged in meaning: the configuration's intention. Anything scraping it
	// keeps getting what it has always got.
	metric("skopos_firewall_enforcing", "1 when blocks are applied to the kernel.", "gauge",
		boolValue(s.deps.Firewall.Enforcing()))

	// What the kernel was last found to hold, which is a different question.
	// Added beside the old gauge rather than redefining it: a dashboard built
	// on the old meaning would otherwise change what it says without anyone
	// touching it, which is its own kind of dishonesty.
	fwState := s.deps.Firewall.State()
	metric("skopos_firewall_kernel_verified",
		"1 when the kernel was read back and held what Skopos programmed.", "gauge",
		boolValue(fwState.Verdict == firewall.VerdictEnforcing))
	metric("skopos_firewall_kernel_sets_checked",
		"1 when the last check could also confirm no rule set sits empty.", "gauge",
		boolValue(fwState.SetsChecked))
	// Absent rather than zero when the kernel has never been read: a zero
	// timestamp is 1970, and an alert on "older than 10 minutes" would fire
	// forever on a monitor-only install instead of staying quiet.
	if !fwState.CheckedAt.IsZero() {
		metric("skopos_firewall_kernel_checked_timestamp_seconds",
			"When the kernel was last read back, in seconds since the epoch.", "gauge",
			float64(fwState.CheckedAt.UnixNano())/1e9)
	}
	if !fwState.FailingSince.IsZero() {
		metric("skopos_firewall_kernel_failing_since_seconds",
			"When the kernel first stopped matching, in seconds since the epoch.", "gauge",
			float64(fwState.FailingSince.UnixNano())/1e9)
	}

	// Findings the policy worker could not keep up with. Dropping them beats
	// stalling packet capture, but it is not something to keep quiet about:
	// a non-zero value here means alerts and blocks went missing.
	if s.deps.PolicyDropped != nil {
		metric("skopos_findings_dropped_total",
			"Detector findings discarded because the policy queue was full.",
			"counter", float64(s.deps.PolicyDropped()))
	}

	blocks, err := s.deps.Store.ActiveBlocks(ctx)
	if err == nil {
		metric("skopos_active_blocks", "Blocks currently in effect.", "gauge", float64(len(blocks)))
	}
	if unacked, err := s.deps.Store.CountUnackedAlerts(ctx); err == nil {
		metric("skopos_unacked_alerts", "Alerts not yet acknowledged.", "gauge", float64(unacked))
	}
	if flows, err := s.deps.Store.CountFlows(ctx); err == nil {
		metric("skopos_flows_stored", "Raw flow records in hot storage.", "gauge", float64(flows))
	}
	if devices, err := s.deps.Store.ListDevices(ctx); err == nil {
		metric("skopos_devices", "Devices in the LAN inventory.", "gauge", float64(len(devices)))
	}

	// Per-block attempt counters: the packets the firewall dropped (or would
	// drop while observing), labelled by prefix.
	if s.deps.BlockStats != nil {
		stats := s.deps.BlockStats()
		if len(stats) > 0 {
			b.WriteString("# HELP skopos_block_attempts_total Packets seen from or to a blocked prefix since start.\n")
			b.WriteString("# TYPE skopos_block_attempts_total counter\n")
			prefixes := make([]string, 0, len(stats))
			for p := range stats {
				prefixes = append(prefixes, p)
			}
			sort.Strings(prefixes)
			for _, p := range prefixes {
				fmt.Fprintf(&b, "skopos_block_attempts_total%s %d\n",
					labelSet([]string{"prefix", p}), stats[p].Attempts)
			}
		}
	}

	if s.deps.CountryBlockStats != nil {
		counts, _ := s.deps.CountryBlockStats()
		if len(counts) > 0 {
			b.WriteString("# HELP skopos_country_prefixes Networks loaded into the kernel per blocked country.\n")
			b.WriteString("# TYPE skopos_country_prefixes gauge\n")
			codes := make([]string, 0, len(counts))
			for c := range counts {
				codes = append(codes, c)
			}
			sort.Strings(codes)
			for _, c := range codes {
				fmt.Fprintf(&b, "skopos_country_prefixes%s %d\n", labelSet([]string{"country", c}), counts[c])
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// labelSet renders alternating key/value pairs as a Prometheus label set.
func labelSet(kv []string) string {
	if len(kv) < 2 {
		return ""
	}
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, fmt.Sprintf("%s=%q", kv[i], escapeLabel(kv[i+1])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// escapeLabel escapes the three characters the exposition format reserves in
// label values.
func escapeLabel(v string) string {
	return strings.NewReplacer("\\", `\\`, "\"", `\"`, "\n", `\n`).Replace(v)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
