-- Block provenance, and the indexes that make the audit log queryable.
--
-- A block has carried one free-text reason since 0001. "portscan: 22 ports in
-- 60s" is a sentence, not a trail: nothing in the row points at the alert that
-- said it, so answering "why is this blocked" meant matching an address and a
-- rough time by eye against a separate list — and for a block placed by hand,
-- asking the person who placed it. These four columns are the trail: who, on
-- what observation, and the alert or incident it can be followed back to.
--
-- Nullable, with no default, deliberately. Every block already in this table
-- was recorded before Skopos kept provenance and genuinely does not know who
-- placed it. DEFAULT '' would make those rows indistinguishable from a block
-- recorded today by an actor nobody named, and a plausible back-fill ('admin',
-- 'system', the origin repeated as an actor) would be a fabricated attribution
-- in the one table an operator opens to find out who did this. NULL is the
-- only value that means "not recorded", and the read path renders it as that:
-- no provenance at all, rather than an actor.
--
-- actor is the column that carries the distinction. It is written whenever
-- provenance is recorded, so actor IS NULL is exactly "this block predates
-- provenance", and the scan builds no provenance record for such a row.
--
-- No foreign key on alert_id / incident_id on purpose. Retention prunes alerts
-- and incidents on their own schedules; a reference would either block that
-- delete or quietly blank the link, and a block outliving its evidence is
-- normal. The number stays, and a lookup that finds nothing means the alert
-- has aged out — which is a true answer, and a different one from "no alert
-- was ever recorded".
--
-- ADD COLUMN with no default rewrites no rows: SQLite records the column in
-- the schema and reads the absent trailing value as NULL.

ALTER TABLE blocks ADD COLUMN actor       TEXT;    -- who placed it; NULL = predates provenance
ALTER TABLE blocks ADD COLUMN evidence    TEXT;    -- the observation it rests on
ALTER TABLE blocks ADD COLUMN alert_id    INTEGER; -- alert that caused it, if any
ALTER TABLE blocks ADD COLUMN incident_id INTEGER; -- incident it belongs to, if any

-- Audit filtering. The log could only be read newest-first under a LIMIT, so
-- past the last entries on screen "who blocked this, and when" was
-- unanswerable: the only way to look further back was to raise the limit until
-- the whole table — which has no retention — came back through the one
-- connection every other query queues behind.
--
-- actor and action are matched exactly. They are values Skopos itself writes,
-- so filtering means picking one, and these two indexes turn those filters
-- into a seek plus an ordered walk instead of a scan of the whole log.
--
-- target deliberately gets no index. It is matched on a leading prefix,
-- because the same address is written two ways here — a block records
-- 203.0.113.5/32 while a login records the bare address — and an operator
-- types the address, not the mask. SQLite cannot answer a LIKE prefix from an
-- index unless the whole database is switched to case-sensitive LIKE, which
-- would also stop a MAC typed in lowercase from finding one recorded in upper.
-- The time index from 0001 bounds that walk, and this table takes a handful of
-- rows per operator action, not per packet.

CREATE INDEX idx_audit_actor_time  ON audit (actor, time_ms);
CREATE INDEX idx_audit_action_time ON audit (action, time_ms);
