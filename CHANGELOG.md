# Changelog

All notable changes to Skopos are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-08-13

### Fixed

- **The device list inventories devices again.** It used to file the
  link-layer address of any frame whose IP side looked local, so a subnet
  broadcast became a neighbour called `192.168.1.255 (ff:ff:ff:ff:ff:ff)` and
  every mDNS or SSDP group got an entry of its own. Group addresses belong to
  no machine and are now skipped, and the upgrade removes the entries they
  already left behind — except any you named, restricted or watched, which are
  kept whatever they look like.
- **One address no longer grows a dozen entries.** Traffic that presents a
  fresh hardware address per sighting — a tunnel, a relay re-framing other
  hosts' packets, a NIC randomising its MAC — used to add an inventory row and
  a "new device" alert every time. An address that several MACs have claimed
  has shown that its MAC means nothing, so it stops creating entries, and the
  list offers to clear out the ones already there.
- **Dual-stack devices keep both addresses.** IPv4 and IPv6 have separate
  columns, so a device that last spoke over IPv6 no longer shows
  `fe80::8f5:45d3:3bc2:b3ea` where its LAN address used to be. A link-local
  address never displaces a routable one, and a per-device policy now covers
  both families — a quarantine with a working IPv6 path was not a quarantine.
- **Capture handles links that are not Ethernet.** On a VPN tunnel, a PPP link
  or a 6in4 interface there is no Ethernet header, and reading the first
  fourteen bytes as one invented hardware addresses that never existed. Those
  interfaces are now parsed as what they carry: bare IP packets, with no MACs.
- **"Abuse 0%" no longer sits next to a critical alert.** An address no free
  source happened to have data on was rendered as a confident green zero,
  which reads as "this one is fine" — including for addresses Skopos had just
  matched against a blocklist itself. Nothing found now says so: unknown, not
  cleared, never green.
- **The country is where the address is.** It came from the registry, which
  records where the address holder is incorporated — so a Dutch data centre
  whose operator is registered in Andorra was reported as Andorra. The local
  GeoIP database answers first now, and a registry country is labelled
  "Registered in" so the difference is visible rather than misleading.

### Added

- **Devices you can find and tidy.** The list has a search box, shows both of
  a device's addresses, marks randomised MACs as what they are, and can forget
  an entry — singly, or all the noise at once after showing you exactly which
  entries it means. Forgetting is safe: discovery is passive, so anything
  still on the network is back within seconds.
- **Hostnames without asking anyone.** Devices that announce themselves over
  mDNS are inventoried under that name, so the list reads "printer.local"
  instead of a bare MAC address.
- **More sources behind "who is this?"** — the blocklists Skopos already
  downloads (answered from memory, no request), blocklist.de's fail2ban
  reports alongside DShield's sensor data, and the local GeoIP database. Each
  source's answer is shown separately, so a number can be checked instead of
  trusted, and the strongest reading wins rather than being averaged away by
  sources that have never heard of the address. Still no account and no API
  key anywhere. Where the free sources are thin, the card links straight to
  the AbuseIPDB, Shodan and VirusTotal pages for the address — plain links,
  nothing is sent until you click one.

## [0.3.0] - 2026-08-13

Skopos learns your network's language. Traffic arrives with names instead of
addresses, the dashboard can be steered without touching a file, and every
control says exactly how far it reaches.

### Added

- **Names instead of addresses** — Skopos now reads the DNS and mDNS answers
  and TLS server names that pass the wire, so flows, top destinations and
  alerts show `youtube.com` where they used to show `142.250.185.78`. Learned
  passively from traffic Skopos already sees: nothing is queried, nothing is
  sent anywhere, and names survive restarts.
- **Domains view** — which domains the network contacted, by volume, for the
  last hour/day/week, and the same list per device on its detail page.
- **TLS client fingerprints (JA4)** — each device's TLS handshakes are
  fingerprinted, identifying client software independently of address or
  port. Shown per device; the same browser keeps the same fingerprint even
  when it shuffles cipher order.
- **Prometheus metrics** — `/metrics` now actually exists (the config knob
  had nothing behind it): throughput, enforcement state, active blocks,
  unacked alerts, per-block drop counters and per-country prefix counts.
- **Behavioural baseline** — Skopos learns each device's usual hourly volume
  and reports departures from it: the printer that suddenly uploads a
  gigabyte, the camera that starts talking at 3am. It needs a few hours of
  history before it judges anything, has an absolute floor so a quiet device
  cannot alert over a kilobyte, and never suggests a block — unusual is not
  malicious.
- **Search the history** — the Traffic view can query the raw flow records by
  address (or CIDR), port, protocol, direction and domain over a window, for
  the question the aggregates cannot answer: what actually happened at 3am.
- **Notification buttons** — ntfy pushes carry "Block 24h" and "Mute"
  buttons. Each is a signed, single-purpose, expiring link: a leaked
  notification grants one temporary block of one address, never API access.
  They appear once `server.external_url` is set.
- **Mirror-port mode** — declare a switch SPAN/tap interface under
  `capture.mirror.interfaces` and Skopos sees the whole segment instead of
  only this machine's traffic. The System view says which of the two you are
  getting, since visibility and enforcement have different reach.
- **Incidents** — the Alerts view groups events by source and episode: one
  attacker with forty scan attempts is one row saying "40 events", expandable
  to the individual alerts, acknowledgeable in one click. Two hours of quiet
  starts a new episode, so today's visit is not merged with last week's. The
  flat list stays one click away.
- **Mute rules** — silence an alert pattern by detector, source prefix, port
  or any combination, permanently or with a TTL. Muting stops the alert and
  the notification and nothing else: blocking still applies exactly as
  configured, because a noise control that quietly disarmed protection would
  be a trap.
- **Per-device policy** — confine a device from its detail page: "LAN only"
  drops its traffic to and from the internet, "Quarantine" drops everything
  including local traffic. Implemented as kernel rules keyed on the device's
  address, ahead of the conntrack exemption so an established connection is
  cut too, and re-derived every 30 seconds so a DHCP lease change follows the
  device. The UI states plainly that this reaches only traffic passing the
  machine running Skopos.
- **Settings you can actually change** — enforcement, automatic block
  lifetime, alert cooldown, the never-block allowlist and both threshold
  detectors are now editable in the dashboard and apply immediately. No
  file editing, no restart: arming the firewall is one click. The YAML
  stays the baseline, the UI marks what you changed away from it, and
  "Reset to config.yaml" drops every override. Invalid values are refused
  as a whole, so a bad patch can never leave the firewall half-armed, and
  every change lands in the audit log.
- **Release check** — a daily look at the public releases page, a banner in
  the System view and one notification per new version, so a stale image
  cannot go unnoticed. Off with `updates.check: false`.

### Changed

- **IP reputation now works without any account.** Attack history comes from
  DShield (SANS Internet Storm Center) alongside RDAP ownership — both open,
  keyless sources — so the "who is this?" lookup is fully populated on a
  fresh install instead of asking the operator to register for an API key
  and paste it into Settings. The API-key handling and its Settings card are
  gone with it.

## [0.2.2] - 2026-08-13

Country blocking learns the difference between an attack and an answer.

### Fixed

- Reactive country blocking no longer blocks the far end of connections your
  own devices opened. It used to fire on the reply packets that the conntrack
  exemption deliberately lets through — killing exactly the traffic the
  exemption protects (Skopos' own RDAP lookup against a Brazilian registry
  being the first casualty). It now reacts only to inbound connection
  attempts (TCP SYN).
- Sources already dropped by the preventive country sets no longer generate
  "Traffic from blocked country" alerts and redundant per-IP blocks; the
  kernel handles them, the live view badges them.
- The live view's `blocked` badge is honest now: it only appears when
  enforcement is actually active (observe mode drops nothing), and flows
  covered by country blocking are badged too — previously only per-IP blocks
  were.

## [0.2.1] - 2026-08-13

Blocking you can believe: the firewall now proves it is working, whole
countries are dropped preventively, and observe mode stops pretending.

### Added

- **World map** — the Traffic view renders the country statistics as a
  choropleth (outbound/inbound toggle), volume-scaled in the accent hue.
- **Preventive country blocking** — listed countries' networks are enumerated
  from the GeoIP database and loaded into dedicated kernel sets, so their
  traffic is dropped on arrival instead of only after a source has already
  appeared once. Inbound-only behind a conntrack exemption: connections your
  own devices open toward those countries keep working. The country chips
  show how many networks are loaded; the reactive block-on-sight detector
  stays as backstop while the database is still downloading.
- **Proof the firewall works** — every block now counts the packets seen
  from/to its prefix ("Dropped" in enforce mode, "Would drop" in observe
  mode, with the last-attempt time), and live-view flows touching an active
  block carry a `blocked` badge. The capture tap sits before netfilter, so
  blocked traffic remains visible while the kernel discards it — previously
  that read as "blocking doesn't work".

### Changed

- **Observe mode is now unmistakable.** The Firewall view banners when
  enforcement is off ("nothing is actually blocked") or the backend is
  unavailable, the Overview tile turns amber in observe mode, and alerts for
  sources the kernel already drops are suppressed — their ongoing attempts
  show in the per-block counters instead of re-alerting as if the block had
  failed.

### Fixed

- Blocklist feeds no longer raise alerts for bogon space. Border lists like
  FireHOL Level 1 include multicast, broadcast, CGNAT and RFC1918 ranges by
  design; inside a LAN those matched everyday mDNS/SSDP/DHCP traffic and
  produced critical alerts for addresses like 239.255.255.250. Feed matches
  now only consider routable public unicast addresses.

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

[Unreleased]: https://github.com/julianhintermann-cmd/skopos/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.1
[0.3.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.3.0
[0.2.2]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.2
[0.2.1]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.1
[0.2.0]: https://github.com/julianhintermann-cmd/skopos/releases/tag/v0.2.0
[0.1.0]: https://github.com/julianhintermann-cmd/skopos/commit/57a56c1
