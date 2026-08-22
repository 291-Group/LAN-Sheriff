-- The schema as it existed at migration 2, before the M2 storage optimization.
--
-- Kept verbatim because it is the shape of every database created by an early
-- build, and because a test that constructs it from current code would not be
-- testing an upgrade at all. The distinguishing feature is `flow_key TEXT NOT
-- NULL UNIQUE`, which the optimization replaced with an integer `flow_hash`.
CREATE TABLE endpoints (
  ip            TEXT PRIMARY KEY,
  rdns          TEXT,
  asn           INTEGER,
  org           TEXT,
  country       TEXT,
  country_name  TEXT,
  city          TEXT,
  lat           REAL,
  lon           REAL,
  is_internal   INTEGER NOT NULL DEFAULT 0,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  enriched_at   INTEGER
);

CREATE TABLE devices (
  id            TEXT PRIMARY KEY,
  mac           TEXT,
  ip            TEXT,
  hostname      TEXT,
  vendor        TEXT,
  device_type   TEXT,
  label         TEXT,
  trust         TEXT NOT NULL DEFAULT 'unknown',
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  online        INTEGER NOT NULL DEFAULT 0,
  suspicion     REAL NOT NULL DEFAULT 0,
  is_self       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE flows (
  id            INTEGER PRIMARY KEY,
  flow_key      TEXT NOT NULL UNIQUE,
  ts_start      INTEGER NOT NULL,
  ts_last       INTEGER NOT NULL,
  device_id     TEXT,
  process       TEXT,
  pid           INTEGER,
  src_ip        TEXT,
  src_port      INTEGER,
  dst_ip        TEXT,
  dst_port      INTEGER,
  proto         TEXT,
  bytes_out     INTEGER DEFAULT 0,
  bytes_in      INTEGER DEFAULT 0,
  active        INTEGER NOT NULL DEFAULT 1,
  suspicion     REAL NOT NULL DEFAULT 0
, direction TEXT NOT NULL DEFAULT 'out');
CREATE INDEX idx_flows_ts ON flows(ts_last);
CREATE INDEX idx_flows_dst ON flows(dst_ip);
CREATE INDEX idx_flows_device ON flows(device_id);
CREATE INDEX idx_flows_process ON flows(process);
CREATE INDEX idx_flows_direction ON flows(direction, ts_last);

CREATE TABLE dns_events (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  device_id     TEXT,
  process       TEXT,
  qname         TEXT NOT NULL,
  qtype         TEXT,
  answers       TEXT,
  resp_ms       INTEGER,
  flagged       TEXT
);

CREATE TABLE rollups (
  bucket_ts     INTEGER NOT NULL,
  key_type      TEXT NOT NULL,
  key           TEXT NOT NULL,
  conns         INTEGER DEFAULT 0,
  bytes_out     INTEGER DEFAULT 0,
  bytes_in      INTEGER DEFAULT 0,
  PRIMARY KEY (bucket_ts, key_type, key)
);

CREATE TABLE findings (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  subject_type  TEXT NOT NULL,
  subject       TEXT NOT NULL,
  rule          TEXT NOT NULL,
  score         REAL NOT NULL,
  detail        TEXT,
  status        TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE settings (
  key           TEXT PRIMARY KEY,
  value         TEXT NOT NULL
);

CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
INSERT INTO schema_migrations (version) VALUES (1), (2);
