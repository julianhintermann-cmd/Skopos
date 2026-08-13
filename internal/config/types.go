// Package config defines Skopos' single YAML configuration file: its typed
// structure, defaults, environment-variable interpolation, strict parsing
// and validation. The field doc comments in this file are the single source
// of truth for the generated JSON schema and the configuration reference.
package config

// Config is the root of config.yaml. Every field has a working default:
// an empty file is a valid configuration that monitors the default-route
// interface, enforces nothing and sends no notifications.
type Config struct {
	// Interfaces lists the network interfaces to capture on, e.g.
	// ["eth0", "eth1"]. The special value "auto" resolves to the interface
	// of the default route at startup.
	Interfaces []string `yaml:"interfaces" json:"interfaces,omitempty"`

	// Network groups address-classification settings shared by capture,
	// detection and the firewall.
	Network Network `yaml:"network" json:"network,omitzero"`

	// Storage configures the hot (SSD) and cold (HDD/NAS) data paths and
	// how long data is retained at each resolution.
	Storage Storage `yaml:"storage" json:"storage,omitzero"`

	// Capture tunes packet capture and metadata enrichment.
	Capture Capture `yaml:"capture" json:"capture,omitzero"`

	// Detection configures the detectors that decide what counts as
	// suspicious, and how alerts are throttled.
	Detection Detection `yaml:"detection" json:"detection,omitzero"`

	// Firewall configures blocking behaviour and the nftables backend.
	Firewall Firewall `yaml:"firewall" json:"firewall,omitzero"`

	// Notify configures alert delivery (ntfy and a generic webhook).
	Notify Notify `yaml:"notify" json:"notify,omitzero"`

	// Server configures the web dashboard, API, authentication and TLS.
	Server Server `yaml:"server" json:"server,omitzero"`

	// Logging configures log verbosity and file logging to cold storage.
	Logging Logging `yaml:"logging" json:"logging,omitzero"`

	// Metrics configures the optional Prometheus endpoint.
	Metrics Metrics `yaml:"metrics" json:"metrics,omitzero"`

	// Updates configures the daily release check.
	Updates Updates `yaml:"updates" json:"updates,omitzero"`

	// Demo replaces live capture with a synthetic traffic generator so the
	// dashboard can be explored without any privileges or real traffic.
	Demo bool `yaml:"demo" json:"demo,omitempty"`
}

// Network groups address-classification settings.
type Network struct {
	// PrivateRanges are the CIDR ranges treated as "internal" when
	// classifying traffic (LAN↔WAN, LAN↔LAN) and choosing block behaviour.
	// Defaults to RFC 1918, IPv6 ULA and link-local ranges.
	PrivateRanges []string `yaml:"private_ranges" json:"private_ranges,omitempty"`
}

// Storage configures data locations and retention.
type Storage struct {
	// Hot is the fast storage path (SSD): SQLite database, runtime state
	// and the spool buffer. Mount this on your SSD volume.
	Hot string `yaml:"hot" json:"hot,omitempty"`

	// Cold is the archive path (HDD or NAS share): Parquet flow archives,
	// rotated logs, alert archive and database backups. Skopos keeps
	// working when this path is temporarily unavailable and spools to hot
	// storage instead.
	Cold string `yaml:"cold" json:"cold,omitempty"`

	// HotMaxSize caps total hot-storage usage (database plus spool). When
	// the cap is reached the oldest raw flows are dropped first; aggregated
	// rollups are kept.
	HotMaxSize Size `yaml:"hot_max_size" json:"hot_max_size,omitzero"`

	// SpoolMaxSize caps the spool buffer used while cold storage is
	// unreachable. When the spool is full, the oldest spooled archives are
	// dropped and a system notification is sent.
	SpoolMaxSize Size `yaml:"spool_max_size" json:"spool_max_size,omitzero"`

	// Retention controls how long each data resolution is kept on hot
	// storage before deletion (raw flows are archived to cold first).
	Retention Retention `yaml:"retention" json:"retention,omitzero"`

	// ArchiveAt is the local time of day at which raw flows older than the
	// retention window are exported to cold storage. Missed runs are
	// caught up at the next start.
	ArchiveAt ClockTime `yaml:"archive_at" json:"archive_at,omitzero"`

	// Backup configures the daily SQLite online backup to cold storage.
	Backup Backup `yaml:"backup" json:"backup,omitzero"`
}

// Retention controls per-resolution lifetimes on hot storage.
type Retention struct {
	// RawFlows is how long individual flow records stay in the database
	// before being archived to cold storage as Parquet and deleted.
	RawFlows Duration `yaml:"raw_flows" json:"raw_flows,omitzero"`

	// Rollup1m is how long 1-minute aggregates are kept.
	Rollup1m Duration `yaml:"rollup_1m" json:"rollup_1m,omitzero"`

	// Rollup1h is how long 1-hour aggregates are kept.
	Rollup1h Duration `yaml:"rollup_1h" json:"rollup_1h,omitzero"`

	// Rollup1d is how long daily aggregates are kept. "0" keeps them
	// forever.
	Rollup1d Duration `yaml:"rollup_1d" json:"rollup_1d,omitzero"`
}

// Backup configures SQLite online backups.
type Backup struct {
	// Enabled turns the daily database backup to cold storage on or off.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// Keep is the number of backup generations retained on cold storage.
	Keep int `yaml:"keep" json:"keep,omitempty"`

	// At is the local time of day the backup runs.
	At ClockTime `yaml:"at" json:"at,omitzero"`
}

// Capture tunes packet capture and enrichment.
type Capture struct {
	// SampleThresholdPPS is the packets-per-second rate above which
	// adaptive sampling kicks in to protect the NAS CPU. The transition is
	// reported as a system event, never silent. "0" disables sampling.
	SampleThresholdPPS int `yaml:"sample_threshold_pps" json:"sample_threshold_pps,omitempty"`

	// DNS enables parsing DNS responses (names only) so the dashboard can
	// show hostnames instead of bare IPs.
	DNS bool `yaml:"dns" json:"dns,omitempty"`

	// SNI enables parsing TLS ClientHello server names (metadata only).
	SNI bool `yaml:"sni" json:"sni,omitempty"`

	// RDNS enables cached, rate-limited reverse-DNS lookups for external
	// addresses shown in the dashboard.
	RDNS bool `yaml:"rdns" json:"rdns,omitempty"`

	// Devices enables the LAN device inventory built from ARP/NDP traffic
	// and mDNS/DHCP names. Required by the new_device detector.
	Devices bool `yaml:"devices" json:"devices,omitempty"`

	// FlowFlush is how often aggregated flow counters are flushed from
	// memory to the database.
	FlowFlush Duration `yaml:"flow_flush" json:"flow_flush,omitzero"`

	// FlowIdleTimeout is how long a flow may stay silent before it is
	// considered finished and flushed.
	FlowIdleTimeout Duration `yaml:"flow_idle_timeout" json:"flow_idle_timeout,omitzero"`
}

// Detection configures detectors and alert policy.
type Detection struct {
	// Portscan detects vertical scans (many ports on one target) and
	// horizontal scans (one port across many targets).
	Portscan Portscan `yaml:"portscan" json:"portscan,omitzero"`

	// Rate detects connection floods and abnormal packet rates per source.
	Rate RateDetector `yaml:"rate" json:"rate,omitzero"`

	// Feeds matches traffic against public IP blocklists (FireHOL Level 1,
	// Spamhaus DROP) refreshed at runtime.
	Feeds Feeds `yaml:"feeds" json:"feeds,omitzero"`

	// NewDevice raises an alert when an unknown device appears in the LAN.
	NewDevice NewDevice `yaml:"new_device" json:"new_device,omitzero"`

	// Cooldown is the minimum interval between notifications for the same
	// (detector, source) pair; additional hits are counted and included in
	// the next notification instead of spamming.
	Cooldown Duration `yaml:"cooldown" json:"cooldown,omitzero"`

	// QuietHours suppresses notifications below a minimum severity during
	// a nightly time window.
	QuietHours QuietHours `yaml:"quiet_hours" json:"quiet_hours,omitzero"`
}

// Portscan configures the port-scan detector.
type Portscan struct {
	// Enabled turns the detector on or off.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// Window is the sliding time window for counting distinct ports and
	// targets.
	Window Duration `yaml:"window" json:"window,omitzero"`

	// External holds thresholds for sources outside the private ranges.
	External ScanThresholds `yaml:"external" json:"external,omitzero"`

	// Internal holds thresholds for sources inside the private ranges
	// (set higher: legitimate LAN tools scan more).
	Internal ScanThresholds `yaml:"internal" json:"internal,omitzero"`

	// Severity assigned to port-scan alerts: info, warning or critical.
	Severity string `yaml:"severity" json:"severity,omitempty"`

	// Block requests an automatic block for offending sources. Only acts
	// when firewall.enforcement is "enforce".
	Block bool `yaml:"block" json:"block,omitempty"`
}

// ScanThresholds are port-scan trigger levels within the window.
type ScanThresholds struct {
	// Ports is the number of distinct destination ports on a single target
	// that triggers a vertical-scan alert.
	Ports int `yaml:"ports" json:"ports,omitempty"`

	// Targets is the number of distinct targets on the same port that
	// triggers a horizontal-scan alert.
	Targets int `yaml:"targets" json:"targets,omitempty"`
}

// RateDetector configures the rate/flood detector.
type RateDetector struct {
	// Enabled turns the detector on or off.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// Window is the measurement window.
	Window Duration `yaml:"window" json:"window,omitzero"`

	// MaxNewConnections is the number of new connections from one source
	// within the window that triggers an alert.
	MaxNewConnections int `yaml:"max_new_connections" json:"max_new_connections,omitempty"`

	// MaxPacketsPerSecond is the sustained packet rate from one source
	// that triggers an alert.
	MaxPacketsPerSecond int `yaml:"max_packets_per_second" json:"max_packets_per_second,omitempty"`

	// Severity assigned to rate alerts: info, warning or critical.
	Severity string `yaml:"severity" json:"severity,omitempty"`

	// Block requests an automatic block for offending sources. Only acts
	// when firewall.enforcement is "enforce".
	Block bool `yaml:"block" json:"block,omitempty"`
}

// Feeds configures blocklist-feed matching.
type Feeds struct {
	// Enabled turns feed matching on or off. Recommended when the NAS is
	// reachable from the internet; in a pure LAN it mostly produces noise.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// Lists selects the feeds: the built-in names "firehol_level1" and
	// "spamhaus_drop", or any https:// URL serving one CIDR per line.
	Lists []string `yaml:"lists" json:"lists,omitempty"`

	// Refresh is how often feeds are re-downloaded.
	Refresh Duration `yaml:"refresh" json:"refresh,omitzero"`

	// Severity assigned to feed-hit alerts: info, warning or critical.
	Severity string `yaml:"severity" json:"severity,omitempty"`

	// Block requests an automatic block for feed-listed peers. Only acts
	// when firewall.enforcement is "enforce".
	Block bool `yaml:"block" json:"block,omitempty"`
}

// NewDevice configures the new-device detector.
type NewDevice struct {
	// Enabled turns the detector on or off (requires capture.devices).
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// Severity assigned to new-device alerts: info, warning or critical.
	Severity string `yaml:"severity" json:"severity,omitempty"`
}

// QuietHours suppresses low-severity notifications during a time window.
type QuietHours struct {
	// Enabled turns quiet hours on or off.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`

	// From is the local start time of the quiet window.
	From ClockTime `yaml:"from" json:"from,omitzero"`

	// To is the local end time of the quiet window (may cross midnight).
	To ClockTime `yaml:"to" json:"to,omitzero"`

	// MinSeverity is the lowest severity still delivered during quiet
	// hours: info, warning or critical.
	MinSeverity string `yaml:"min_severity" json:"min_severity,omitempty"`
}

// Firewall configures blocking behaviour.
type Firewall struct {
	// Enforcement is the global switch: "observe" logs every block
	// decision without touching the kernel (the shipping default), while
	// "enforce" applies blocks through the backend. Arm it deliberately
	// after watching the observe log for a while.
	Enforcement string `yaml:"enforcement" json:"enforcement,omitempty"`

	// Backend selects the firewall implementation. "nftables" (the only
	// backend in v1) manages a dedicated "inet skopos" table via netlink.
	Backend string `yaml:"backend" json:"backend,omitempty"`

	// BlockTTL is the default lifetime of automatic blocks; they expire in
	// the kernel via nftables set timeouts. Manual blocks default to
	// permanent. "0" makes automatic blocks permanent too.
	BlockTTL Duration `yaml:"block_ttl" json:"block_ttl,omitzero"`

	// ActionExternal is what happens to blocked traffic from outside the
	// private ranges: "drop" (silent) or "reject" (immediate error).
	ActionExternal string `yaml:"action_external" json:"action_external,omitempty"`

	// ActionInternal is what happens to blocked traffic from inside the
	// private ranges: "drop" or "reject" ("reject" fails fast and is
	// friendlier when a LAN block turns out to be a mistake).
	ActionInternal string `yaml:"action_internal" json:"action_internal,omitempty"`

	// Allowlist lists IPs/CIDRs that are never blocked, not even by feeds.
	// The default gateway is always protected in addition to this list.
	Allowlist []string `yaml:"allowlist" json:"allowlist,omitempty"`

	// Blocklist lists IPs/CIDRs that are always blocked while enforcement
	// is "enforce" — declarative, versionable static blocks.
	Blocklist []string `yaml:"blocklist" json:"blocklist,omitempty"`
}

// Notify configures alert delivery.
type Notify struct {
	// Ntfy configures push notifications through a self-hosted ntfy server
	// or ntfy.sh (same API).
	Ntfy Ntfy `yaml:"ntfy" json:"ntfy,omitzero"`

	// Webhook posts every alert as JSON to a URL of your choice.
	Webhook Webhook `yaml:"webhook" json:"webhook,omitzero"`

	// System controls operational notifications (start after crash,
	// firewall degraded, cold storage unreachable, feed update failed,
	// update available).
	System SystemNotify `yaml:"system" json:"system,omitzero"`
}

// Ntfy configures the ntfy notifier.
type Ntfy struct {
	// URL is the base URL of the ntfy server, e.g.
	// "https://ntfy.example.com" or "https://ntfy.sh". Empty disables ntfy.
	URL string `yaml:"url" json:"url,omitempty"`

	// Topic is the ntfy topic to publish to.
	Topic string `yaml:"topic" json:"topic,omitempty"`

	// Token is an ntfy access token (sent as Bearer). Supports ${ENV}
	// interpolation so secrets can stay out of the file.
	Token string `yaml:"token" json:"token,omitempty"`

	// Username enables HTTP basic auth as an alternative to Token.
	Username string `yaml:"username" json:"username,omitempty"`

	// Password is the basic-auth password. Supports ${ENV} interpolation.
	Password string `yaml:"password" json:"password,omitempty"`
}

// Webhook configures the generic JSON webhook notifier.
type Webhook struct {
	// URL receives a JSON POST per alert. Empty disables the webhook.
	URL string `yaml:"url" json:"url,omitempty"`
}

// SystemNotify controls operational notifications.
type SystemNotify struct {
	// Enabled turns system notifications on or off.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`
}

// Server configures the web dashboard and API.
type Server struct {
	// Bind is the listen address. With network_mode: host this is a real
	// host address; keep 0.0.0.0 unless you know you need otherwise.
	Bind string `yaml:"bind" json:"bind,omitempty"`

	// Port is the web/API port. With network_mode: host there is no port
	// mapping — this is the port your browser connects to.
	Port int `yaml:"port" json:"port,omitempty"`

	// ExternalURL is the address under which you reach the dashboard from
	// your devices (used as the click target of push notifications), e.g.
	// "https://skopos.example.com" or "http://192.168.1.10:8686".
	ExternalURL string `yaml:"external_url" json:"external_url,omitempty"`

	// Auth configures dashboard and API authentication.
	Auth Auth `yaml:"auth" json:"auth,omitzero"`

	// Tokens are named API tokens for automation (scripts, Home
	// Assistant). Scope "read" allows GET, "write" also allows mutations.
	Tokens []APIToken `yaml:"tokens" json:"tokens,omitempty"`

	// TLS serves HTTPS directly from Skopos. Usually you terminate TLS at
	// a reverse proxy instead and leave this empty.
	TLS TLS `yaml:"tls" json:"tls,omitzero"`
}

// Auth configures authentication.
type Auth struct {
	// Mode is "single_admin" (username + Argon2 hash below), or "none"
	// (only for trusted LANs — Skopos logs a prominent warning). Default:
	// "single_admin" as soon as password_hash is set, otherwise "none".
	Mode string `yaml:"mode" json:"mode,omitempty"`

	// Username is the admin login name.
	Username string `yaml:"username" json:"username,omitempty"`

	// PasswordHash is the Argon2id hash of the admin password. Generate it
	// with: skopos hash-password
	PasswordHash string `yaml:"password_hash" json:"password_hash,omitempty"`

	// SessionTTL is how long a login session stays valid.
	SessionTTL Duration `yaml:"session_ttl" json:"session_ttl,omitzero"`
}

// APIToken is a named API token.
type APIToken struct {
	// Name identifies the token in the audit log.
	Name string `yaml:"name" json:"name"`

	// Token is the secret value (sent as "Authorization: Bearer …").
	// Supports ${ENV} interpolation.
	Token string `yaml:"token" json:"token"`

	// Scope is "read" or "write".
	Scope string `yaml:"scope" json:"scope"`
}

// TLS configures optional native TLS.
type TLS struct {
	// Cert is the path to the PEM certificate chain.
	Cert string `yaml:"cert" json:"cert,omitempty"`

	// Key is the path to the PEM private key.
	Key string `yaml:"key" json:"key,omitempty"`
}

// Logging configures logs.
type Logging struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level" json:"level,omitempty"`

	// File enables structured JSON logs in rotated files under
	// <storage.cold>/logs in addition to the readable stdout log.
	File bool `yaml:"file" json:"file,omitempty"`

	// MaxSize is the size at which the current log file is rotated.
	MaxSize Size `yaml:"max_size" json:"max_size,omitzero"`

	// MaxBackups is the number of rotated log files to keep.
	MaxBackups int `yaml:"max_backups" json:"max_backups,omitempty"`
}

// Metrics configures the Prometheus endpoint.
type Metrics struct {
	// Enabled serves Prometheus metrics on /metrics.
	Enabled bool `yaml:"enabled" json:"enabled,omitempty"`
}

// Updates configures the release check.
type Updates struct {
	// Check asks GitHub's public releases endpoint once a day whether a
	// newer Skopos exists, shows the answer in the System view and sends one
	// notification per new version. Nothing is transmitted but the request
	// itself. On by default — a monitoring tool that silently runs a stale
	// image is worse than one that asks.
	Check bool `yaml:"check" json:"check"`
}
