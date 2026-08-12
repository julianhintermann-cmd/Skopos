-- Cloudflare zones the operator has connected. The list is refreshed from the
-- API on connect; the monitored flag is set in the UI and preserved across
-- refreshes. The API token itself is not stored here — it is sealed with
-- AES-GCM and kept in the meta table under an encrypted value.
CREATE TABLE cf_zones (
    id         TEXT    PRIMARY KEY,          -- Cloudflare zone id
    name       TEXT    NOT NULL,             -- domain, e.g. example.com
    status     TEXT    NOT NULL DEFAULT '',  -- active, pending, …
    monitored  INTEGER NOT NULL DEFAULT 1,
    added_ms   INTEGER NOT NULL
);
