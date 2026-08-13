-- Per-device network policy: what a device is allowed to reach. The classic
-- case is an IoT gadget that has no business talking to the internet at all.
ALTER TABLE devices ADD COLUMN policy TEXT NOT NULL DEFAULT '';

-- Alert suppression rules: the operator's answer to "stop telling me about
-- this". Matching is by detector, source prefix and port, each optional.
CREATE TABLE mute_rules (
    id          INTEGER PRIMARY KEY,
    detector    TEXT    NOT NULL DEFAULT '',
    prefix      TEXT    NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 0,
    reason      TEXT    NOT NULL DEFAULT '',
    created_ms  INTEGER NOT NULL,
    expires_ms  INTEGER
);
CREATE INDEX idx_mute_rules_detector ON mute_rules (detector);

-- Incidents group related alerts (same source, one episode) so the Alerts
-- view can show "one attacker, 40 events" instead of 40 rows.
CREATE TABLE incidents (
    id          INTEGER PRIMARY KEY,
    source      TEXT    NOT NULL,
    first_ms    INTEGER NOT NULL,
    last_ms     INTEGER NOT NULL,
    severity    TEXT    NOT NULL,
    detectors   TEXT    NOT NULL DEFAULT '',
    alert_count INTEGER NOT NULL DEFAULT 0,
    title       TEXT    NOT NULL DEFAULT '',
    ack         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_incidents_last ON incidents (last_ms);
CREATE INDEX idx_incidents_source ON incidents (source);

ALTER TABLE alerts ADD COLUMN incident_id INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_alerts_incident ON alerts (incident_id);
