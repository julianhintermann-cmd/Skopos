-- Initial schema: flows, rollups, alerts, blocks, devices and audit log.
-- All timestamps are Unix milliseconds in UTC. IP addresses are stored as
-- text (canonical netip form) for portability and readable ad-hoc queries.

CREATE TABLE flows (
    id          INTEGER PRIMARY KEY,
    start_ms    INTEGER NOT NULL,
    end_ms      INTEGER NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    src_port    INTEGER NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       INTEGER NOT NULL,
    direction   TEXT    NOT NULL,
    out_bytes   INTEGER NOT NULL,
    out_packets INTEGER NOT NULL,
    in_bytes    INTEGER NOT NULL,
    in_packets  INTEGER NOT NULL,
    dst_name    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_flows_start ON flows (start_ms);
CREATE INDEX idx_flows_src   ON flows (src_ip, start_ms);
CREATE INDEX idx_flows_dst   ON flows (dst_ip, start_ms);

-- Rollups share a shape across resolutions. bucket_ms is the truncated bucket
-- start; the (bucket_ms, src_ip, dst_ip, dst_port, proto, direction) tuple is
-- unique so ingestion can upsert-accumulate.
CREATE TABLE rollup_1m (
    bucket_ms   INTEGER NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       INTEGER NOT NULL,
    direction   TEXT    NOT NULL,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    flows       INTEGER NOT NULL,
    PRIMARY KEY (bucket_ms, src_ip, dst_ip, dst_port, proto, direction)
) WITHOUT ROWID;
CREATE INDEX idx_rollup_1m_bucket ON rollup_1m (bucket_ms);

CREATE TABLE rollup_1h (
    bucket_ms   INTEGER NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       INTEGER NOT NULL,
    direction   TEXT    NOT NULL,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    flows       INTEGER NOT NULL,
    PRIMARY KEY (bucket_ms, src_ip, dst_ip, dst_port, proto, direction)
) WITHOUT ROWID;
CREATE INDEX idx_rollup_1h_bucket ON rollup_1h (bucket_ms);

CREATE TABLE rollup_1d (
    bucket_ms   INTEGER NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER NOT NULL,
    proto       INTEGER NOT NULL,
    direction   TEXT    NOT NULL,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    flows       INTEGER NOT NULL,
    PRIMARY KEY (bucket_ms, src_ip, dst_ip, dst_port, proto, direction)
) WITHOUT ROWID;
CREATE INDEX idx_rollup_1d_bucket ON rollup_1d (bucket_ms);

CREATE TABLE alerts (
    id         INTEGER PRIMARY KEY,
    time_ms    INTEGER NOT NULL,
    detector   TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    source     TEXT    NOT NULL DEFAULT '',
    title      TEXT    NOT NULL,
    detail     TEXT    NOT NULL DEFAULT '',
    count      INTEGER NOT NULL DEFAULT 1,
    ack        INTEGER NOT NULL DEFAULT 0,
    ack_ms     INTEGER
);
CREATE INDEX idx_alerts_time ON alerts (time_ms);
CREATE INDEX idx_alerts_ack  ON alerts (ack, time_ms);

CREATE TABLE blocks (
    id         INTEGER PRIMARY KEY,
    prefix     TEXT    NOT NULL,
    origin     TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_ms INTEGER NOT NULL,
    expires_ms INTEGER,
    active     INTEGER NOT NULL DEFAULT 1,
    removed_ms INTEGER
);
CREATE UNIQUE INDEX idx_blocks_active_prefix ON blocks (prefix) WHERE active = 1;
CREATE INDEX idx_blocks_active ON blocks (active);

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    mac         TEXT    NOT NULL UNIQUE,
    ip          TEXT    NOT NULL DEFAULT '',
    hostname    TEXT    NOT NULL DEFAULT '',
    vendor      TEXT    NOT NULL DEFAULT '',
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);
CREATE INDEX idx_devices_last_seen ON devices (last_seen_ms);

CREATE TABLE audit (
    id       INTEGER PRIMARY KEY,
    time_ms  INTEGER NOT NULL,
    actor    TEXT    NOT NULL,
    action   TEXT    NOT NULL,
    target   TEXT    NOT NULL DEFAULT '',
    detail   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_time ON audit (time_ms);

-- Small key/value table for singleton runtime state (HMAC session key, last
-- archive run, schema bookkeeping that is not a migration).
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
