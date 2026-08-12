# Security Policy

Skopos captures network traffic and manages a host firewall, so it asks for
real privileges. This document explains exactly what it needs, why, how those
privileges are constrained, and how to report a vulnerability.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead,
report privately via GitHub Security Advisories
([Report a vulnerability](https://github.com/julianhintermann-cmd/skopos/security/advisories/new))
or contact the maintainer at [@julianhintermann-cmd](https://github.com/julianhintermann-cmd).

You can expect an acknowledgement within a few days. Please include the version,
your `config.yaml` (with secrets redacted), and steps to reproduce.

## Threat model

Skopos is designed to run on a home or small-office NAS, reachable from the
local network and — for the operator — optionally from the internet through a
reverse proxy or VPN. The assets it protects are the traffic history, the alert
and audit records, and the firewall state. The adversaries it considers are:

- **Untrusted hosts on the LAN or WAN** scanning or flooding the NAS. Skopos
  detects and (optionally) blocks them. It never trusts packet contents: the
  parser is bounds-checked against malformed frames and only reads headers.
- **A stolen dashboard session or API token.** Auth is required by default;
  tokens are scoped; every privileged action is audited.
- **A compromised feed or config value.** Blocklist feeds are size-capped and
  parsed defensively; configuration is validated before use; the app never
  executes configuration.

Out of scope for v1: deep packet inspection, defending against a kernel-level
compromise of the host, and protecting against an operator who already has root
on the NAS.

## Why these privileges

Skopos runs with **host networking** and exactly **two Linux capabilities**.
Each is required by a core feature and nothing more:

| Privilege | Enables | Why it cannot be avoided | Constraint |
| --------- | ------- | ------------------------ | ---------- |
| `NET_RAW` | AF_PACKET packet capture | Reading traffic off an interface needs a raw socket | Only packet **headers** and DNS/SNI **names** are processed; raw packets are never written to disk |
| `NET_ADMIN` | nftables management via netlink | Setting firewall rules needs admin access to the network stack | Skopos only touches its **own** `inet skopos` table; the gateway and allowlist are never blocked; `observe` mode touches nothing |
| `network_mode: host` | Sight of the host's interfaces and firewall | A container in its own netns can only see its own traffic and cannot protect the host | Exactly one port is opened (default 8686); authentication and a login backoff guard it |

Everything else is dropped. The reference `docker-compose.yml` ships with:

- `cap_drop: [ALL]` then `cap_add: [NET_ADMIN, NET_RAW]` — no other capability
  is present, not even for root inside the container.
- `security_opt: [no-new-privileges:true]` — the process can never gain
  privileges via setuid binaries.
- `read_only: true` with `tmpfs: [/tmp]` — the root filesystem is immutable;
  the app writes only to the `/data` and `/archive` volumes.
- `mem_limit` and `cpus` — a resource ceiling.

The process runs as root **inside the container**, but because all capabilities
except the two above are dropped and no-new-privileges is set, that root is
confined to packet capture and firewall management. Running as a non-root user
with file capabilities is a planned hardening step; it does not change the
capability set the container is granted.

## Safe by default

- **Firewall is in `observe` mode out of the box.** Skopos logs what it *would*
  block but changes nothing until you deliberately set `enforcement: enforce`.
- **The gateway can never be blocked**, nor anything in your allowlist — a
  last-resort safety so Skopos cannot lock you out of your own network.
- **Auto-block is off by default** on every detector; you enable it per rule.
- **Authentication is on** whenever a password hash is configured; `auth: none`
  is a deliberate choice that logs a prominent warning and is meant only for a
  trusted LAN behind other controls.
- **No telemetry.** Skopos phones home only for an optional version check
  against the GitHub releases API, which you can disable.

## Supported versions

Until 1.0, security fixes land on the latest minor release. Pin a version tag
in production and watch releases for advisories.
