-- Periodic internet speed measurements (Cloudflare speed endpoints).
CREATE TABLE speedtest_results (
    id          INTEGER PRIMARY KEY,
    time_ms     INTEGER NOT NULL,
    down_mbps   REAL    NOT NULL,
    up_mbps     REAL    NOT NULL,
    latency_ms  REAL    NOT NULL
);
CREATE INDEX idx_speedtest_time ON speedtest_results (time_ms);
