-- Capture coverage: what the capture was doing during each bucket, written on
-- a heartbeat rather than when packets arrive.
--
-- The rollups record nothing for a minute with no traffic and nothing for a
-- minute with no capture, so today those two leave byte-identical state and a
-- chart draws a clean interpolated line straight through an outage. These
-- tables are what tell them apart, and they are what lets a stored byte count
-- carry the keep rate it is a fraction of instead of being shown as a total.
--
-- Purely additive. Nothing before this migration has coverage, and those
-- buckets must read as "not recorded" rather than be back-filled with an
-- assumption: a guess promoted to history is exactly the class of untruth this
-- release exists to remove.
--
-- Resolutions mirror the rollups so retention, ChooseResolution and the query
-- path line up with no special cases. No secondary index: the primary key is
-- the range key every query uses.

CREATE TABLE coverage_1m (
  bucket_ms        INTEGER PRIMARY KEY,
  sources_total    INTEGER NOT NULL, -- capture sources configured this bucket
  sources_up       INTEGER NOT NULL, -- ...of which alive for the whole bucket
  observed_packets INTEGER NOT NULL, -- true, pre-sampling count (exact)
  kept_packets     INTEGER NOT NULL, -- survived sampling; == observed when not sampling
  seconds_covered  INTEGER NOT NULL  -- heartbeats landed, 0..60
);

CREATE TABLE coverage_1h (
  bucket_ms        INTEGER PRIMARY KEY,
  sources_total    INTEGER NOT NULL,
  sources_up       INTEGER NOT NULL,
  observed_packets INTEGER NOT NULL,
  kept_packets     INTEGER NOT NULL,
  seconds_covered  INTEGER NOT NULL  -- 0..3600
);

CREATE TABLE coverage_1d (
  bucket_ms        INTEGER PRIMARY KEY,
  sources_total    INTEGER NOT NULL,
  sources_up       INTEGER NOT NULL,
  observed_packets INTEGER NOT NULL,
  kept_packets     INTEGER NOT NULL,
  seconds_covered  INTEGER NOT NULL  -- 0..86400
);
