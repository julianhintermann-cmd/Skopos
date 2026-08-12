# Skopos

> **σκοπός** — the watcher. Traffic monitoring, firewall management and
> ntfy alerting for your NAS, in a single container configured by a single
> YAML file.

**Status: under active development — heading for v0.1.0.**
This README will grow into the full setup and configuration reference as the
first release comes together. The architecture and roadmap live in the
project documentation.

## What Skopos will do

- **Traffic monitoring** — live capture on the host's interfaces (AF_PACKET),
  aggregated into flows, with device inventory and readable names (DNS/SNI).
- **Firewall management** — block/unblock IPs and CIDRs through a dedicated
  nftables table with TTL sets; declarative state that survives reboots;
  `observe` mode by default so nothing blocks until you arm it.
- **ntfy alerts** — port scans, rate anomalies, blocklist hits and new devices,
  with per-rule cooldowns so one scan is one push, not five hundred.
- **Web dashboard** — live throughput, traffic explorer, devices, firewall,
  alert history. Light and dark, English UI.
- **One YAML** — every path, interface, threshold, topic and credential comes
  from `config.yaml`. No hardcoded environment assumptions; hot storage (SSD)
  and cold archive (HDD/NAS share) are two independent volumes.

## License

[AGPL-3.0](LICENSE) — free for everyone to run, study, share and improve;
network services built on modified versions must publish their source.
