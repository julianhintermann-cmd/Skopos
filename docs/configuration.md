# Configuration reference

_This file is generated from the config struct by `go generate ./...`. Do not edit by hand._

Skopos is configured by a single YAML file (default `/config/config.yaml`, override with `SKOPOS_CONFIG` or `--config`). Every option has a working default; an empty file is valid. String values support `${VAR}` and `${VAR:-default}` environment interpolation.

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `interfaces` | list of string | `[auto]` | Interfaces lists the network interfaces to capture on, e.g. ["eth0", "eth1"]. The special value "auto" resolves to the interface of the default route at startup. Naming an interface fed by a switch's mirror/SPAN port makes Skopos see the whole LAN's traffic rather than only this machine's — see capture.mirror. |
| **`network`** | object | | Network groups address-classification settings shared by capture, detection and the firewall. |
| `network.private_ranges` | list of string | `[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10]` | PrivateRanges are the CIDR ranges treated as "internal" when classifying traffic (LAN↔WAN, LAN↔LAN) and choosing block behaviour. Defaults to RFC 1918, IPv6 ULA and link-local ranges. |
| **`storage`** | object | | Storage configures the hot (SSD) and cold (HDD/NAS) data paths and how long data is retained at each resolution. |
| `storage.hot` | string | `/data` | Hot is the fast storage path (SSD): SQLite database and runtime state. Mount this on your SSD volume. |
| `storage.cold` | string | `/archive` | Cold is the archive path (HDD or NAS share) for the daily database backup. Skopos keeps running when this path is unavailable; the backup is skipped and reported. |
| `storage.hot_max_size` | string | `5GiB` | HotMaxSize caps hot-storage usage. When the cap is reached the oldest raw flows are deleted first; aggregated rollups are kept. |
| `storage.spool_max_size` | string | `2GiB` | SpoolMaxSize is reserved for a spool buffer that does not exist yet. It is accepted so existing configuration files keep loading, and has no effect. Nothing is spooled today. |
| **`storage.retention`** | object | | Retention controls how long each data resolution is kept on hot storage before it is deleted. |
| `storage.retention.raw_flows` | string | `7d` | RawFlows is how long individual flow records stay in the database before they are deleted. The rollups outlive them. |
| `storage.retention.rollup_1m` | string | `90d` | Rollup1m is how long 1-minute aggregates are kept. |
| `storage.retention.rollup_1h` | string | `730d` | Rollup1h is how long 1-hour aggregates are kept. |
| `storage.retention.rollup_1d` | string |  | Rollup1d is how long daily aggregates are kept. "0" keeps them forever. |
| `storage.archive_at` | string | `03:00` | ArchiveAt is reserved for an export-to-cold job that does not exist yet. It is accepted so existing configuration files keep loading, and has no effect. Raw flows past their retention are deleted, not exported; the daily backup is the durable copy. |
| **`storage.backup`** | object | | Backup configures the daily SQLite online backup to cold storage. |
| `storage.backup.enabled` | boolean | `true` | Enabled turns the daily database backup to cold storage on or off. |
| `storage.backup.keep` | integer | `14` | Keep is the number of backup generations retained on cold storage. |
| `storage.backup.at` | string | `03:30` | At is the local time of day the backup runs. |
| **`capture`** | object | | Capture tunes packet capture and metadata enrichment. |
| `capture.sample_threshold_pps` | integer | `80000` | SampleThresholdPPS is the packets-per-second rate above which adaptive sampling kicks in to protect the NAS CPU. The transition is reported as a system event, never silent. "0" disables sampling. |
| `capture.dns` | boolean | `true` | DNS enables parsing DNS responses (names only) so the dashboard can show hostnames instead of bare IPs. |
| `capture.sni` | boolean | `true` | SNI enables parsing TLS ClientHello server names (metadata only). |
| `capture.rdns` | boolean | `true` | RDNS enables cached, rate-limited reverse-DNS lookups for external addresses shown in the dashboard. |
| `capture.devices` | boolean | `true` | Devices enables the LAN device inventory built from ARP/NDP traffic and mDNS/DHCP names. Required by the new_device detector. |
| `capture.flow_flush` | string | `10s` | FlowFlush is how often aggregated flow counters are flushed from memory to the database. |
| `capture.flow_idle_timeout` | string | `1m0s` | FlowIdleTimeout is how long a flow may stay silent before it is considered finished and flushed. |
| **`capture.mirror`** | object | | Mirror declares which interfaces carry mirrored traffic from a switch's SPAN port or a tap. |
| `capture.mirror.interfaces` | list of string |  | Interfaces are fed by a switch's mirror/SPAN port, or a tap: they carry other devices' traffic, not this machine's. Declaring them changes nothing about how packets are captured — it tells Skopos that what it sees is the whole segment, so the dashboard can say plainly that visibility is network-wide while blocking still only acts on traffic passing this machine's kernel. |
| **`detection`** | object | | Detection configures the detectors that decide what counts as suspicious, and how alerts are throttled. |
| **`detection.portscan`** | object | | Portscan detects vertical scans (many ports on one target) and horizontal scans (one port across many targets). |
| `detection.portscan.enabled` | boolean | `true` | Enabled turns the detector on or off. |
| `detection.portscan.window` | string | `1m0s` | Window is the sliding time window for counting distinct ports and targets. |
| **`detection.portscan.external`** | object | | External holds thresholds for sources outside the private ranges. |
| `detection.portscan.external.ports` | integer | `15` | Ports is the number of distinct destination ports on a single target that triggers a vertical-scan alert. |
| `detection.portscan.external.targets` | integer | `20` | Targets is the number of distinct targets on the same port that triggers a horizontal-scan alert. |
| **`detection.portscan.internal`** | object | | Internal holds thresholds for sources inside the private ranges (set higher: legitimate LAN tools scan more). |
| `detection.portscan.internal.ports` | integer | `30` | Ports is the number of distinct destination ports on a single target that triggers a vertical-scan alert. |
| `detection.portscan.internal.targets` | integer | `40` | Targets is the number of distinct targets on the same port that triggers a horizontal-scan alert. |
| `detection.portscan.severity` | string | `warning` | Severity assigned to port-scan alerts: info, warning or critical. |
| `detection.portscan.block` | boolean |  | Block requests an automatic block for offending sources. Only acts when firewall.enforcement is "enforce". |
| **`detection.rate`** | object | | Rate detects connection floods and abnormal packet rates per source. |
| `detection.rate.enabled` | boolean | `true` | Enabled turns the detector on or off. |
| `detection.rate.window` | string | `10s` | Window is the measurement window. |
| `detection.rate.max_new_connections` | integer | `300` | MaxNewConnections is the number of new connections from one source within the window that triggers an alert. |
| `detection.rate.max_packets_per_second` | integer | `8000` | MaxPacketsPerSecond is the sustained packet rate from one source that triggers an alert. |
| `detection.rate.severity` | string | `warning` | Severity assigned to rate alerts: info, warning or critical. |
| `detection.rate.block` | boolean |  | Block requests an automatic block for offending sources. Only acts when firewall.enforcement is "enforce". |
| **`detection.feeds`** | object | | Feeds matches traffic against public IP blocklists (FireHOL Level 1, Spamhaus DROP) refreshed at runtime. |
| `detection.feeds.enabled` | boolean |  | Enabled turns feed matching on or off. Recommended when the NAS is reachable from the internet; in a pure LAN it mostly produces noise. |
| `detection.feeds.lists` | list of string | `[firehol_level1, spamhaus_drop]` | Lists selects the feeds: the built-in names "firehol_level1" and "spamhaus_drop", or any https:// URL serving one CIDR per line. |
| `detection.feeds.refresh` | string | `1d` | Refresh is how often feeds are re-downloaded. |
| `detection.feeds.severity` | string | `critical` | Severity assigned to feed-hit alerts: info, warning or critical. |
| `detection.feeds.block` | boolean |  | Block requests an automatic block for feed-listed peers. Only acts when firewall.enforcement is "enforce". |
| **`detection.new_device`** | object | | NewDevice raises an alert when an unknown device appears in the LAN. |
| `detection.new_device.enabled` | boolean | `true` | Enabled turns the detector on or off (requires capture.devices). |
| `detection.new_device.severity` | string | `info` | Severity assigned to new-device alerts: info, warning or critical. |
| `detection.cooldown` | string | `30m0s` | Cooldown is the minimum interval between notifications for the same (detector, source) pair; additional hits are counted and included in the next notification instead of spamming. |
| **`detection.quiet_hours`** | object | | QuietHours suppresses notifications below a minimum severity during a nightly time window. |
| `detection.quiet_hours.enabled` | boolean |  | Enabled turns quiet hours on or off. |
| `detection.quiet_hours.from` | string | `23:00` | From is the local start time of the quiet window. |
| `detection.quiet_hours.to` | string | `07:00` | To is the local end time of the quiet window (may cross midnight). |
| `detection.quiet_hours.min_severity` | string | `critical` | MinSeverity is the lowest severity still delivered during quiet hours: info, warning or critical. |
| **`firewall`** | object | | Firewall configures blocking behaviour and the nftables backend. |
| `firewall.enforcement` | string | `observe` | Enforcement is the global switch: "observe" logs every block decision without touching the kernel (the shipping default), while "enforce" applies blocks through the backend. Arm it deliberately after watching the observe log for a while. |
| `firewall.backend` | string | `nftables` | Backend selects the firewall implementation. "nftables" (the only backend in v1) manages a dedicated "inet skopos" table via netlink. |
| `firewall.block_ttl` | string | `1d` | BlockTTL is the default lifetime of automatic blocks; they expire in the kernel via nftables set timeouts. Manual blocks default to permanent. "0" makes automatic blocks permanent too. |
| `firewall.action_external` | string | `drop` | ActionExternal is what happens to blocked traffic from outside the private ranges: "drop" (silent) or "reject" (immediate error). |
| `firewall.action_internal` | string | `reject` | ActionInternal is what happens to blocked traffic from inside the private ranges: "drop" or "reject" ("reject" fails fast and is friendlier when a LAN block turns out to be a mistake). |
| `firewall.allowlist` | list of string |  | Allowlist lists IPs/CIDRs that are never blocked, not even by feeds. The default gateway is always protected in addition to this list. |
| `firewall.blocklist` | list of string |  | Blocklist lists IPs/CIDRs that are always blocked while enforcement is "enforce" — declarative, versionable static blocks. |
| **`notify`** | object | | Notify configures alert delivery (ntfy and a generic webhook). |
| **`notify.ntfy`** | object | | Ntfy configures push notifications through a self-hosted ntfy server or ntfy.sh (same API). |
| `notify.ntfy.url` | string |  | URL is the base URL of the ntfy server, e.g. "https://ntfy.example.com" or "https://ntfy.sh". Empty disables ntfy. |
| `notify.ntfy.topic` | string | `skopos` | Topic is the ntfy topic to publish to. |
| `notify.ntfy.token` | string |  | Token is an ntfy access token (sent as Bearer). Supports ${ENV} interpolation so secrets can stay out of the file. |
| `notify.ntfy.username` | string |  | Username enables HTTP basic auth as an alternative to Token. |
| `notify.ntfy.password` | string |  | Password is the basic-auth password. Supports ${ENV} interpolation. |
| **`notify.webhook`** | object | | Webhook posts every alert as JSON to a URL of your choice. |
| `notify.webhook.url` | string |  | URL receives a JSON POST per alert. Empty disables the webhook. |
| **`notify.system`** | object | | System controls operational notifications (start after crash, firewall degraded, cold storage unreachable, feed update failed, update available). |
| `notify.system.enabled` | boolean | `true` | Enabled turns system notifications on or off. |
| **`server`** | object | | Server configures the web dashboard, API, authentication and TLS. |
| `server.bind` | string | `0.0.0.0` | Bind is the listen address. With network_mode: host this is a real host address; keep 0.0.0.0 unless you know you need otherwise. |
| `server.port` | integer | `8686` | Port is the web/API port. With network_mode: host there is no port mapping — this is the port your browser connects to. |
| `server.external_url` | string |  | ExternalURL is the address under which you reach the dashboard from your devices (used as the click target of push notifications), e.g. "https://skopos.example.com" or "http://192.168.1.10:8686". |
| **`server.auth`** | object | | Auth configures dashboard and API authentication. |
| `server.auth.mode` | string |  | Mode is "single_admin" (username + Argon2 hash below), or "none" (only for trusted LANs — Skopos logs a prominent warning). Default: "single_admin" as soon as password_hash is set, otherwise "none". |
| `server.auth.username` | string | `admin` | Username is the admin login name. |
| `server.auth.password_hash` | string |  | PasswordHash is the Argon2id hash of the admin password. Generate it with: skopos hash-password |
| `server.auth.session_ttl` | string | `30d` | SessionTTL is how long a login session stays valid. |
| `server.tokens` | list of object |  | Tokens are named API tokens for automation (scripts, Home Assistant). Scope "read" allows GET, "write" also allows mutations. |
| **`server.tls`** | object | | TLS serves HTTPS directly from Skopos. Usually you terminate TLS at a reverse proxy instead and leave this empty. |
| `server.tls.cert` | string |  | Cert is the path to the PEM certificate chain. |
| `server.tls.key` | string |  | Key is the path to the PEM private key. |
| **`logging`** | object | | Logging configures log verbosity and file logging to cold storage. |
| `logging.level` | string | `info` | Level is one of debug, info, warn, error. |
| `logging.file` | boolean | `true` | File enables structured JSON logs in rotated files under <storage.cold>/logs in addition to the readable stdout log. |
| `logging.max_size` | string | `50MiB` | MaxSize is the size at which the current log file is rotated. |
| `logging.max_backups` | integer | `10` | MaxBackups is the number of rotated log files to keep. |
| **`metrics`** | object | | Metrics configures the optional Prometheus endpoint. |
| `metrics.enabled` | boolean |  | Enabled serves Prometheus metrics on /metrics. |
| **`updates`** | object | | Updates configures the daily release check. |
| `updates.check` | boolean | `true` | Check asks GitHub's public releases endpoint once a day whether a newer Skopos exists, shows the answer in the System view and sends one notification per new version. Nothing is transmitted but the request itself. On by default — a monitoring tool that silently runs a stale image is worse than one that asks. |
| `demo` | boolean |  | Demo replaces live capture with a synthetic traffic generator so the dashboard can be explored without any privileges or real traffic. |

See [`deploy/config.example.yaml`](../deploy/config.example.yaml) for a fully-commented example.
