-- Direction in the rollups: of a bucket's bytes, how many travelled from the
-- flow's source to its destination.
--
-- Every raw flow has carried out_bytes/in_bytes since 0001. WriteFlows added
-- them together and stored the sum, so the split survived only as long as the
-- 7-day raw window and no screen in Skopos could show upload apart from
-- download — a camera uploading 4 GB overnight and an evening of streaming
-- were the same bar. The number was already in hand at the write; only the
-- column was missing.
--
-- Nullable, with no default, deliberately. A row written before this migration
-- genuinely does not know its split, and DEFAULT 0 would assert that every
-- byte of the last three months was inbound — a fabricated measurement, in the
-- right units, indistinguishable from a real one, in the two tables kept for
-- 90 and 730 days. NULL is the only value that means "not recorded", and the
-- query path renders it as that rather than as a zero-height band.
--
-- NULL then has to survive both aggregation paths, which it does not do by
-- default in SQLite: the upsert adds plainly (out_bytes + excluded.out_bytes,
-- never COALESCE) so a bucket straddling this migration stays unrecorded, and
-- every read guards SUM with COUNT(out_bytes) = COUNT(*), because SUM skips
-- NULLs and would otherwise report the post-migration rows' upload as if it
-- were the whole group's.
--
-- ADD COLUMN with no default rewrites no rows: SQLite records the column in
-- the schema and reads the absent trailing value as NULL, so this is O(1) on a
-- WITHOUT ROWID table at the 5 GiB hot cap, not a copy of the two largest
-- tables in the database.

ALTER TABLE rollup_1m ADD COLUMN out_bytes INTEGER;
ALTER TABLE rollup_1h ADD COLUMN out_bytes INTEGER;
ALTER TABLE rollup_1d ADD COLUMN out_bytes INTEGER;
