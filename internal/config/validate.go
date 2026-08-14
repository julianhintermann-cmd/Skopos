package config

import (
	"fmt"
	"net/netip"
	"strings"
)

var validSeverities = map[string]bool{"info": true, "warning": true, "critical": true}
var validActions = map[string]bool{"drop": true, "reject": true}
var validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

// Validate checks the configuration for consistency and returns a single
// error listing every problem found, so users fix one round of issues
// instead of playing whack-a-mole.
func (c *Config) Validate() error {
	var problems []string
	bad := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if len(c.Interfaces) == 0 {
		bad("interfaces: must not be empty (use [auto])")
	}
	for _, r := range c.Network.PrivateRanges {
		if !validCIDR(r) {
			bad("network.private_ranges: %q is not a valid CIDR", r)
		}
	}

	if c.Storage.Hot == "" {
		bad("storage.hot: must not be empty")
	}
	if c.Storage.Cold == "" {
		bad("storage.cold: must not be empty")
	}
	if c.Storage.Hot == c.Storage.Cold {
		bad("storage: hot and cold must be different paths (got %q for both)", c.Storage.Hot)
	}
	if c.Storage.HotMaxSize < 256<<20 {
		bad("storage.hot_max_size: must be at least 256MiB (got %s)", c.Storage.HotMaxSize)
	}
	if c.Storage.Retention.RawFlows <= 0 {
		bad("storage.retention.raw_flows: must be positive (0 would delete every raw flow immediately)")
	}
	if c.Storage.Retention.Alerts < 0 {
		bad("storage.retention.alerts: must not be negative (use 0 to keep alerts forever)")
	}
	if c.Storage.Backup.Enabled && c.Storage.Backup.Keep < 1 {
		bad("storage.backup.keep: must be at least 1 when backups are enabled")
	}

	sev := func(field, v string) {
		if !validSeverities[v] {
			bad("%s: %q is not a severity (info, warning, critical)", field, v)
		}
	}
	sev("detection.portscan.severity", c.Detection.Portscan.Severity)
	sev("detection.rate.severity", c.Detection.Rate.Severity)
	sev("detection.feeds.severity", c.Detection.Feeds.Severity)
	sev("detection.new_device.severity", c.Detection.NewDevice.Severity)
	sev("detection.quiet_hours.min_severity", c.Detection.QuietHours.MinSeverity)

	if c.Detection.Portscan.Enabled {
		if c.Detection.Portscan.Window <= 0 {
			bad("detection.portscan.window: must be positive")
		}
		for _, t := range []struct {
			name string
			th   ScanThresholds
		}{{"external", c.Detection.Portscan.External}, {"internal", c.Detection.Portscan.Internal}} {
			if t.th.Ports < 2 {
				bad("detection.portscan.%s.ports: must be at least 2", t.name)
			}
			if t.th.Targets < 2 {
				bad("detection.portscan.%s.targets: must be at least 2", t.name)
			}
		}
	}
	if c.Detection.Rate.Enabled {
		if c.Detection.Rate.Window <= 0 {
			bad("detection.rate.window: must be positive")
		}
		if c.Detection.Rate.MaxNewConnections < 1 && c.Detection.Rate.MaxPacketsPerSecond < 1 {
			bad("detection.rate: at least one of max_new_connections / max_packets_per_second must be set")
		}
	}
	if c.Detection.Feeds.Enabled {
		if len(c.Detection.Feeds.Lists) == 0 {
			bad("detection.feeds.lists: must not be empty when feeds are enabled")
		}
		for _, l := range c.Detection.Feeds.Lists {
			if !isBuiltinFeed(l) && !strings.HasPrefix(l, "https://") {
				bad("detection.feeds.lists: %q is neither a built-in feed (firehol_level1, spamhaus_drop) nor an https:// URL", l)
			}
		}
		if c.Detection.Feeds.Refresh < Duration(3600e9) {
			bad("detection.feeds.refresh: must be at least 1h (be kind to feed providers)")
		}
	}
	if c.Detection.NewDevice.Enabled && !c.Capture.Devices {
		bad("detection.new_device: requires capture.devices: true")
	}

	switch c.Firewall.Enforcement {
	case "observe", "enforce":
	default:
		bad("firewall.enforcement: %q is not valid (observe, enforce)", c.Firewall.Enforcement)
	}
	if c.Firewall.Backend != "nftables" {
		bad("firewall.backend: %q is not supported (nftables)", c.Firewall.Backend)
	}
	if !validActions[c.Firewall.ActionExternal] {
		bad("firewall.action_external: %q is not valid (drop, reject)", c.Firewall.ActionExternal)
	}
	if !validActions[c.Firewall.ActionInternal] {
		bad("firewall.action_internal: %q is not valid (drop, reject)", c.Firewall.ActionInternal)
	}
	for _, list := range []struct {
		name string
		vals []string
	}{{"firewall.allowlist", c.Firewall.Allowlist}, {"firewall.blocklist", c.Firewall.Blocklist}} {
		for _, v := range list.vals {
			if !validCIDROrIP(v) {
				bad("%s: %q is not a valid IP or CIDR", list.name, v)
			}
		}
	}

	if u := c.Notify.Ntfy.URL; u != "" {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			bad("notify.ntfy.url: must start with http:// or https:// (got %q)", u)
		}
		if c.Notify.Ntfy.Topic == "" {
			bad("notify.ntfy.topic: must not be empty when ntfy is configured")
		}
		if c.Notify.Ntfy.Token != "" && c.Notify.Ntfy.Username != "" {
			bad("notify.ntfy: set either token or username/password, not both")
		}
	}
	if u := c.Notify.Webhook.URL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		bad("notify.webhook.url: must start with http:// or https:// (got %q)", u)
	}

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		bad("server.port: %d is not a valid port (1–65535)", c.Server.Port)
	}
	switch c.Server.Auth.Mode {
	case "none":
	case "single_admin":
		if c.Server.Auth.PasswordHash == "" {
			bad("server.auth.password_hash: required for mode single_admin — generate one with: skopos hash-password")
		} else if !strings.HasPrefix(c.Server.Auth.PasswordHash, "$argon2id$") {
			bad("server.auth.password_hash: must be an Argon2id hash — generate one with: skopos hash-password")
		}
		if c.Server.Auth.Username == "" {
			bad("server.auth.username: must not be empty for mode single_admin")
		}
	default:
		bad("server.auth.mode: %q is not valid (single_admin, none)", c.Server.Auth.Mode)
	}
	seenTokens := map[string]bool{}
	for i, t := range c.Server.Tokens {
		if t.Name == "" {
			bad("server.tokens[%d].name: must not be empty", i)
		}
		if len(t.Token) < 16 {
			bad("server.tokens[%d] (%s): token must be at least 16 characters", i, t.Name)
		}
		if t.Scope != "read" && t.Scope != "write" {
			bad("server.tokens[%d] (%s): scope %q is not valid (read, write)", i, t.Name, t.Scope)
		}
		if seenTokens[t.Token] {
			bad("server.tokens[%d] (%s): duplicate token value", i, t.Name)
		}
		seenTokens[t.Token] = true
	}
	if (c.Server.TLS.Cert == "") != (c.Server.TLS.Key == "") {
		bad("server.tls: cert and key must be set together")
	}

	if !validLogLevels[c.Logging.Level] {
		bad("logging.level: %q is not valid (debug, info, warn, error)", c.Logging.Level)
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

func isBuiltinFeed(name string) bool {
	return name == "firehol_level1" || name == "spamhaus_drop"
}

func validCIDR(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

func validCIDROrIP(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
