# Changelog

All notable changes to Skopos are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/julianhintermann-cmd/skopos/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.1.0
