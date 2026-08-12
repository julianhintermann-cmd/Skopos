# Changelog

All notable changes to Skopos are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-12

The dashboard grows up: real-time everything, devices you can name and wake,
Cloudflare and GeoIP context for your traffic, and a hand-built phone
experience.

### Added

- **Live view** — every conversation as it completes, streamed over SSE with
  throughput updating once a second; filter by device, IP, port, protocol or
  direction; pause holds incoming flows aside and counts them on the button.
- **Device naming** — rename any device inline; the label survives restarts,
  is never overwritten by discovery, and takes precedence everywhere —
  including in ntfy alerts ("192.168.1.23 (Living-room TV)"), top talkers,
  blocks and the live feed.
- **Device detail page** — per-device throughput over 24h/7d/30d, top
  destinations with DNS/SNI names, ports with well-known-service labels.
- **Presence tracking** — opt-in arrive/leave notifications per device, with
  hysteresis so a phone parking its Wi-Fi radio does not flap.
- **Wake-on-LAN** — a wake button per device (audited).
- **Cloudflare integration** — connect a scoped API token in the UI (sealed
  with AES-GCM at rest, never in YAML), then monitor per-zone requests, cache
  hit rate and edge-blocked threats for your own domains.
- **GeoIP** — destination and source countries in the Traffic view (DB-IP
  Lite, downloaded at runtime, lookups stay local) and reactive country
  blocking: inbound sources from listed countries are blocked on sight once
  enforcement is on.
- **IP reputation** — a "who is this?" lookup on alerts: owner and country
  via RDAP, plus AbuseIPDB score/reports/ISP with an optional API key.
- **Speedtest monitor** — download/upload/latency every six hours against
  Cloudflare's speed endpoints, with history, on-demand runs and a warning
  when the line drops below half its recent median.
- **Weekly report** — a Sunday-evening ntfy digest: volume with trend, top
  devices by name, alerts per detector, new devices, active blocks.
- **Two-factor authentication** — RFC 6238 TOTP for the single-admin login,
  enrolled via QR code and confirmed with a live code.
- **CSV export** — flows (current range), devices and alerts.
- **Mobile experience** — below 768px the dashboard becomes its own app:
  bottom tab bar, custom bottom sheets instead of dropdowns, and card layouts
  for the live feed and device list.
- **Settings view** — appearance, integrations (Cloudflare, AbuseIPDB), 2FA,
  notification test and version info in one place.

### Changed

- Sidebar navigation grouped into Monitor / Protect / Manage.
- Every `main` build now also publishes an immutable `edge-<commit>` image
  tag next to the moving `edge` tag.

## [0.1.0] - 2026-08-12

The first release: a single container that monitors traffic, manages an
nftables firewall and sends ntfy alerts, configured entirely from one YAML
file.

### Added

- **Traffic monitoring** — AF_PACKET capture with a bounds-checked header
  parser (IPv4/IPv6, VLAN, v6 extension headers), a 5-tuple flow aggregator
  with bidirectional pairing and LAN/WAN classification, an adaptive sampler
  that reports every transition, and a LAN device inventory from ARP/NDP.
- **Storage** — SQLite (WAL) on hot storage with 1m/1h/1d rollups, per-
  resolution retention, a hard hot-size cap that drops oldest raw flows first,
  Parquet archival to cold storage with a spool buffer for when cold is
  offline, and daily online backups.
- **Detection** — port-scan (vertical/horizontal, internal/external
  thresholds), connection-rate, blocklist-feed (FireHOL L1, Spamhaus DROP, or
  any URL, with ETag caching) and new-device detectors.
- **Policy** — severity actions, per-source cooldown with aggregation, quiet
  hours, a never-block allowlist with the gateway hard-wired, and the
  `observe`/`enforce` switch.
- **Firewall** — an nftables backend via netlink (dedicated `inet skopos`
  table, interval+timeout sets, input/forward/output chains), a declarative
  reconciler with restore-on-start and TTL expiry, and graceful degradation to
  monitor-only when the backend is unavailable.
- **Notifications** — ntfy (priority mapping, tags, click-through, token/basic
  auth) and a generic JSON webhook, operational system messages, and a test
  send.
- **API & auth** — REST + SSE, Argon2id single-admin login with signed
  sessions and a login backoff, scoped API tokens, an embedded offline OpenAPI
  reference, and an `auth: none` mode for trusted LANs.
- **Dashboard** — a React + TypeScript UI (Overview, Traffic, Devices,
  Firewall, Alerts, System) with light/dark themes, embedded into the binary.
- **Packaging** — a multi-arch (amd64/arm64) distroless image on GHCR and
  Docker Hub, a reference `docker-compose.yml` with an SSD/HDD volume split, a
  demo mode for a zero-privilege trial, and a full configuration reference
  generated from the source.

[Unreleased]: https://github.com/julianhintermann-cmd/skopos/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.0
[0.1.0]: https://github.com/julianhintermann-cmd/skopos/commit/57a56c1
