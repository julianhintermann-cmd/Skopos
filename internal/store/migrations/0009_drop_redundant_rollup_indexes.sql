-- The rollup tables are WITHOUT ROWID with bucket_ms leading their primary
-- key, so the primary key already range-scans on bucket_ms. These three
-- indexes duplicated it: a second, nearly-complete B-tree over the two
-- largest tables in the database, measured at roughly half the total file
-- size on a year of traffic. Dropping them costs nothing in query plans and
-- gives the hot-size cap back the headroom it was spending on a copy.
DROP INDEX IF EXISTS idx_rollup_1m_bucket;
DROP INDEX IF EXISTS idx_rollup_1h_bucket;
DROP INDEX IF EXISTS idx_rollup_1d_bucket;
