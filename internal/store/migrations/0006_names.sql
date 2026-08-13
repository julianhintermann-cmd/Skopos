-- Passive DNS: address→name mappings learned from DNS/mDNS answers and TLS
-- SNI, plus per-device domain contact counts. Names are what turn a wall of
-- addresses into something an operator can reason about.
CREATE TABLE dns_names (
    ip          TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    source      TEXT    NOT NULL, -- 'dns', 'mdns' or 'sni'
    first_ms    INTEGER NOT NULL,
    last_ms     INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ip, name)
);
CREATE INDEX idx_dns_names_last ON dns_names (last_ms);
CREATE INDEX idx_dns_names_name ON dns_names (name);

-- Which device talked to which domain, and how much. Rolled up per hour so
-- the table stays small on a busy network.
CREATE TABLE domain_contacts (
    hour_ms     INTEGER NOT NULL,
    device_ip   TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    flows       INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour_ms, device_ip, name)
);
CREATE INDEX idx_domain_contacts_hour ON domain_contacts (hour_ms);
CREATE INDEX idx_domain_contacts_name ON domain_contacts (name);

-- TLS client fingerprints (JA4) seen per device: identifies client software
-- independently of address or port.
CREATE TABLE tls_fingerprints (
    device_ip   TEXT    NOT NULL,
    ja4         TEXT    NOT NULL,
    first_ms    INTEGER NOT NULL,
    last_ms     INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (device_ip, ja4)
);
CREATE INDEX idx_tls_fp_last ON tls_fingerprints (last_ms);
