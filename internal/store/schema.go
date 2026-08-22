package store

// migrations are applied in order and recorded, so an existing database is
// upgraded in place rather than rebuilt.
//
// NEVER EDIT A MIGRATION THAT HAS RUN ANYWHERE, INCLUDING IN DEVELOPMENT.
// Append a new one instead. This list is append-only from here on, without
// exception.
//
// That rule is written this strongly because it was broken, and the failure was
// instructive. Migration 1 was rewritten in place during the storage
// optimization, on the reasoning that nothing had shipped yet. But a developer
// database *is* a shipped database: it had already recorded migration 1 as
// applied, so the runner skipped the new text, the table kept its old
// `flow_key TEXT` column, and every flow write then failed against the
// `flow_hash` column the new code expected.
//
// Nothing stops. Endpoint writes go to a table whose schema has not changed and
// carry on succeeding, so the dashboard looks alive while the flow table sits
// frozen, and nothing surfaces the error. See migration 4, and checkSchema,
// which exists so this class of mistake cannot be quiet.
var migrations = []string{
	// 1: the initial schema.
	`
CREATE TABLE IF NOT EXISTS endpoints (
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
CREATE INDEX IF NOT EXISTS idx_endpoints_enriched ON endpoints(enriched_at);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);

CREATE TABLE IF NOT EXISTS devices (
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

-- id stays a plain sequential rowid, and flow_hash carries the flow's identity
-- under a unique index.
--
-- Both halves of that are deliberate. The identity was originally a ~58 byte
-- text key with a 78 byte unique index on it, together 42% of the database; an
-- integer hash costs 8 bytes plus a ~20 byte index. Using that hash *as* the
-- rowid would have saved the index entirely, but hashes arrive in random order
-- and inserting randomly into a B-tree measured 63% slower than appending. The
-- sequential rowid keeps ingest fast; the integer hash keeps the database small.
CREATE TABLE IF NOT EXISTS flows (
  id            INTEGER PRIMARY KEY,
  flow_hash     INTEGER NOT NULL UNIQUE,
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
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_last);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_process ON flows(process);

CREATE TABLE IF NOT EXISTS dns_events (
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
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_events(ts);
CREATE INDEX IF NOT EXISTS idx_dns_qname ON dns_events(qname);

CREATE TABLE IF NOT EXISTS rollups (
  bucket_ts     INTEGER NOT NULL,
  key_type      TEXT NOT NULL,
  key           TEXT NOT NULL,
  conns         INTEGER DEFAULT 0,
  bytes_out     INTEGER DEFAULT 0,
  bytes_in      INTEGER DEFAULT 0,
  PRIMARY KEY (bucket_ts, key_type, key)
);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  subject_type  TEXT NOT NULL,
  subject       TEXT NOT NULL,
  rule          TEXT NOT NULL,
  score         REAL NOT NULL,
  detail        TEXT,
  status        TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, ts);

CREATE TABLE IF NOT EXISTS settings (
  key           TEXT PRIMARY KEY,
  value         TEXT NOT NULL
);
`,
	// 2: record who opened each connection. An inbound connection is a
	// different event from an outbound one and must not be drawn as though the
	// user's own machine reached out.
	`
ALTER TABLE flows ADD COLUMN direction TEXT NOT NULL DEFAULT 'out';
CREATE INDEX IF NOT EXISTS idx_flows_direction ON flows(direction, ts_last);
`,
	// 3: device identity.
	//
	// The original devices table assumed one address and one hardware address
	// per device, which survives neither DHCP nor dual-stack: a phone has an
	// IPv4 and an IPv6 address at once, and its IPv4 address changes on its own
	// schedule. Identity therefore moves out of the row and into its own table,
	// where a device may hold several keys and two rows can be merged when a
	// later observation proves they are the same machine.
	`
-- Identity keys. Several per device, because a device is recognised by whichever
-- of its properties happens to be observable: a hardware address from the
-- neighbour table, a hostname from mDNS. Deliberately NOT keyed on IP address,
-- which DHCP reassigns and which would merge unrelated devices over time.
CREATE TABLE IF NOT EXISTS device_keys (
  key           TEXT PRIMARY KEY,
  device_id     TEXT NOT NULL,
  kind          TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_keys_device ON device_keys(device_id);

-- Every address a device has been seen at, rather than only the current one, so
-- that a flow recorded against an old address still resolves to the right device.
CREATE TABLE IF NOT EXISTS device_addresses (
  device_id     TEXT NOT NULL,
  ip            TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  PRIMARY KEY (device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_device_addresses_ip ON device_addresses(ip);

CREATE TABLE IF NOT EXISTS device_services (
  device_id     TEXT NOT NULL,
  service       TEXT NOT NULL,
  source        TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  PRIMARY KEY (device_id, service)
);

-- name is what the device calls itself; label is what the user called it. They
-- are separate columns because discovery must never overwrite a name a person
-- chose.
ALTER TABLE devices ADD COLUMN name TEXT;
ALTER TABLE devices ADD COLUMN model TEXT;
ALTER TABLE devices ADD COLUMN mac_randomized INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN notes TEXT;
`,
	// 4: normalize the flows table to the canonical shape.
	//
	// Databases created before the storage optimization have `flow_key TEXT
	// UNIQUE`; those created after have `flow_hash INTEGER UNIQUE`. Because
	// migration 1 was wrongly edited in place rather than appended to, both
	// exist in the wild and only one of them works with the current code.
	//
	// This rebuild produces the same table from either starting point. Only
	// columns present in both variants are copied, so it is valid against each,
	// and it is a no-op in effect for a database that was already correct.
	//
	// Historical rows take their rowid as their hash. Their exact value does not
	// matter, a hash exists to deduplicate a flow against later sightings of
	// itself, and a row already written will not be seen again, it only has to
	// be unique, which a rowid is.
	`
CREATE TABLE flows_rebuilt (
  id            INTEGER PRIMARY KEY,
  flow_hash     INTEGER NOT NULL UNIQUE,
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
  suspicion     REAL NOT NULL DEFAULT 0,
  direction     TEXT NOT NULL DEFAULT 'out'
);

INSERT INTO flows_rebuilt
  (id, flow_hash, ts_start, ts_last, device_id, process, pid,
   src_ip, src_port, dst_ip, dst_port, proto, bytes_out, bytes_in,
   active, suspicion, direction)
SELECT
   id, id, ts_start, ts_last, device_id, process, pid,
   src_ip, src_port, dst_ip, dst_port, proto, bytes_out, bytes_in,
   active, suspicion, direction
FROM flows;

DROP TABLE flows;
ALTER TABLE flows_rebuilt RENAME TO flows;

CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_last);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_process ON flows(process);
CREATE INDEX IF NOT EXISTS idx_flows_direction ON flows(direction, ts_last);
`,
	// 5: record why a device was given its type, and let a user's own choice
	// stand.
	//
	// type_reason names the evidence, so the dashboard can say "printer, because
	// it advertises IPP" rather than asking the user to take the label on faith.
	// type_locked marks a type the user set by hand, which re-inference must
	// never overwrite.
	`
ALTER TABLE devices ADD COLUMN type_reason TEXT;
ALTER TABLE devices ADD COLUMN type_locked INTEGER NOT NULL DEFAULT 0;
`,
	// 6: discard discovery-derived names so they re-derive correctly.
	//
	// Before mDNS attribution followed SRV targets, a host advertising on behalf
	// of another was credited with what it advertised, so a Mac sharing a
	// printer took the printer's name, and a device could end up carrying a
	// neighbour's. Those names never correct themselves, because a sighting only
	// fills a name that is empty; it never overwrites one.
	//
	// Only `name` is cleared, which is always discovery-derived. `label` is the
	// user's own and is never touched. Everything cleared here is re-learned
	// within a couple of minutes of the next start.
	`
UPDATE devices SET name = NULL, model = NULL;
DELETE FROM device_services;
DELETE FROM device_keys WHERE kind = 'host';
`,
	// 7: record whether a connection was ever established.
	//
	// Without this, a connection that was attempted and refused is
	// indistinguishable from one that succeeded, and the on-demand port check
	// made that concrete: knocking on 35 ports produced 35 flows, and passive
	// service detection then reported every one of them as a service the device
	// offers. Checking a device fabricated evidence about it.
	`
ALTER TABLE flows ADD COLUMN established INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_flows_established ON flows(established, dst_ip);
`,
	// 8: give findings an identity, so a rule can recognise its own earlier work.
	//
	// Without it a rule that runs every few minutes re-raises the same finding
	// every pass, and the Wanted List becomes a log of one event repeated
	// forever. The key is the rule's own idea of "the same thing": for a first
	// contact it is the device and the organization, not the connection.
	`
ALTER TABLE findings ADD COLUMN dedup TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
  ON findings(dedup) WHERE dedup != '';
`,
	// 9: The Dispatch, paired peers, and the observations they report.
	//
	// Two tables, created empty and staying empty unless the user enables
	// peering. Nothing here runs on its own.
	//
	// The important design is in `peer_summaries`: **the primary key begins with
	// peer_id**, so a peer's observations are namespaced under it at the storage
	// layer rather than by a check somewhere in the merge code. Two peers
	// reporting the same device identifier are two different rows about two
	// different machines, and there is no statement a peer can make that reaches
	// another peer's rows. That is docs/DISPATCH-PROTOCOL.md §8 rule 2, expressed
	// where it cannot be forgotten.
	//
	// Peer data is deliberately kept apart from `flows` and `devices` rather than
	// merged into them. It is a cache with a TTL, it is somebody else's
	// observation, and it must be droppable in one statement when a peer is
	// unpaired or suspended. Mixing it into the local tables would make
	// "everything this peer ever told us" a query rather than a delete, and would
	// put untrusted rows one forgotten WHERE clause away from being read as our
	// own.
	`
CREATE TABLE IF NOT EXISTS peers (
  peer_id     TEXT PRIMARY KEY,
  public_key  BLOB NOT NULL,
  label       TEXT,
  -- 'trusted' or 'suspended'. Suspended keeps the pairing and the connection
  -- while excluding the peer's data, because the useful response to a peer
  -- behaving oddly is to stop believing it, not to lose the ability to watch it.
  trust       TEXT NOT NULL DEFAULT 'trusted',
  paired_at   INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL DEFAULT 0,
  -- Last known address, so a paired peer can be re-found after a DHCP change.
  -- Advisory only: the pinned key decides identity, never the address.
  last_addr   TEXT,
  clock_skew  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS peer_summaries (
  peer_id     TEXT NOT NULL,
  device      TEXT NOT NULL,
  hour        INTEGER NOT NULL,
  org         TEXT NOT NULL DEFAULT '',
  country     TEXT NOT NULL DEFAULT '',
  asn         INTEGER NOT NULL DEFAULT 0,
  app         TEXT NOT NULL DEFAULT '',
  proto       TEXT NOT NULL DEFAULT '',
  port        INTEGER NOT NULL DEFAULT 0,
  flows       INTEGER NOT NULL DEFAULT 0,
  bytes_out   INTEGER NOT NULL DEFAULT 0,
  bytes_in    INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL,
  PRIMARY KEY (peer_id, device, hour, org, app, proto, port)
);

CREATE INDEX IF NOT EXISTS idx_peer_summaries_hour ON peer_summaries(hour);
CREATE INDEX IF NOT EXISTS idx_peer_summaries_received ON peer_summaries(received_at);
`,
	// 10: close beaconing findings raised before the rule counted services.
	//
	// Beaconing used to key a finding on the destination *address*, so a service
	// answering on many addresses became many findings: on a real network, 55
	// findings that were really six services, 27 of them the same one. The rule
	// now groups by organization and produced 8 where it had produced 55.
	//
	// Without this the old rows stay open for the full seven-day TTL, because
	// expiry only closes what stops being seen and nothing refreshes a key the
	// rule no longer emits. Every existing install would show a week of findings
	// its own rules would never raise again.
	//
	// Findings are derived data, the engine recomputes them from flows every
	// five minutes, so closing them costs one rule pass and nothing else. Only
	// beaconing is touched, because only its keying changed. This follows
	// migration 6: a change that leaves bad data behind needs two fixes.
	`
UPDATE findings SET status = 'cleared'
WHERE rule = 'beaconing' AND status = 'open';
`,
	// 11: close rare_destination findings raised before the rule asked *who*.
	//
	// The rule used to treat a country as rare on this network's history alone,
	// which reported a content network answering from a nearby edge as though
	// the traffic had gone somewhere unusual. On a real network that was fifteen
	// reports of Akamai, Google and Amazon being themselves, burying the one
	// destination that deserved a look, a single connection to a government
	// host. The rule now also asks whether the *organization* is one this
	// network already reaches in many countries.
	//
	// As with migration 10: expiry only closes what stops being seen, and
	// nothing refreshes a key the rule no longer emits, so without this the old
	// rows stay open for their full TTL.
	`
UPDATE findings SET status = 'cleared'
WHERE rule = 'rare_destination' AND status = 'open';
`,
	// 12: close findings that rested on a mis-stamped established flag.
	//
	// The Patrol flow assembler reported a connection as established while it
	// was still in its table and as never-connected once it had finished, so a
	// refused connection counted as live and an ordinary completed conversation
	// counted as nothing at all. Six rules filter on that flag. The visible
	// symptom was a report that this machine had "sent VNC traffic unencrypted"
	// to a host that never answered a single packet.
	//
	// Stored flows are deliberately **not** rewritten. The correct value cannot
	// be recovered for a row already written: Deputy records no byte counts, and
	// a Patrol row acquires its process name later, so nothing in the table
	// separates the two sources. A heuristic here would be a guess applied to
	// somebody's data. The rules run on a moving window instead, so mis-stamped
	// rows age out on their own; only the conclusions drawn from them need
	// clearing.
	`
UPDATE findings SET status = 'cleared'
WHERE status = 'open'
  AND rule IN ('plaintext', 'beaconing', 'first_contact', 'port_scan', 'volume');
`,
	// 13: undo the *method* migrations 11 and 12 used, which was wrong.
	//
	// Both marked findings `cleared` to retire conclusions the rules would no
	// longer draw. But `cleared` is **a user's dismissal**, set from the Wanted
	// List, and the upsert in RecordFindings deliberately never reopens one: a
	// finding somebody has dealt with must not reappear every five minutes.
	//
	// So for any finding whose dedup key the rule still emits, which is most of
	// them, since only rare_destination's *inputs* changed and not its keying,
	// the row is updated forever and never seen again. That is the opposite of
	// what was wanted. It would have permanently buried the one finding the
	// rare_destination work existed to surface: a single connection to a
	// government host, previously lost among fifteen reports of content networks.
	//
	// Migration 10 escaped this only by luck. It changed beaconing's keying from
	// address to organization, so the rule emits new keys and inserts new rows;
	// the stale ones simply age out.
	//
	// The correct instrument for derived data is **delete**, not a status a human
	// owns. Only `open` rows are touched, so dismissals and trust decisions
	// survive untouched, and the rules re-insert whatever still holds on their
	// next pass.
	//
	// Migrations 11 and 12 are left exactly as they were rather than corrected in
	// place: they have been applied to real databases, and a migration that has
	// run is history. This is the same shape as migration 6, a change that
	// leaves bad data behind needs a second fix, not an edited first one.
	`
DELETE FROM findings
WHERE status = 'cleared'
  AND rule IN ('rare_destination', 'plaintext', 'beaconing',
               'first_contact', 'port_scan', 'volume');
`,
	// 14: correct the flows migration 12 said could not be corrected.
	//
	// Migration 12 declined to repair rows carrying the mis-stamped established
	// flag, on the grounds that nothing distinguishes a Patrol row from a Deputy
	// one. That was true of the columns considered and false in general, and
	// leaving it meant a live install kept reporting that this machine had sent
	// unencrypted traffic to a host which had never answered a packet, until the
	// rows aged out of the rules' windows, which is days.
	//
	// The distinction is byte accounting. **Deputy never records bytes at all**:
	// it reads socket tables, which carry no counters, so every Deputy row has
	// zero in both directions. Patrol counts whole captured frames. So a TCP row
	// with bytes out and *zero* bytes in was written by Patrol, and cannot have
	// completed a handshake, the SYN-ACK alone would have been counted, and the
	// smallest such frame observed on the wire here is 66 bytes.
	//
	// Narrow on purpose. Rows with no byte accounting are Deputy's and are left
	// exactly alone, so nothing learned from a socket table is second-guessed.
	// UDP is untouched: it has no handshake to fail.
	`
UPDATE flows SET established = 0
WHERE proto = 'tcp' AND established = 1 AND bytes_in = 0 AND bytes_out > 0;

DELETE FROM findings
WHERE status = 'open'
  AND rule IN ('plaintext', 'beaconing', 'first_contact', 'port_scan', 'volume');
`,
	// 15: the rule is called `volume_anomaly`, not `volume`.
	//
	// Migrations 12, 13 and 14 all named a rule that does not exist, so their
	// clauses for it matched nothing. No install here had a volume_anomaly
	// finding to miss (the rule needs three days of history before it speaks)
	// but the omission is real, and the earlier text is left in place because a
	// migration that has run is history.
	//
	// Worth naming the cause rather than only the fix: the string was written
	// from the rule's *file* name. Rule identifiers live in Code(), and that is
	// the only place they should ever be read from.
	`
DELETE FROM findings WHERE status = 'open' AND rule = 'volume_anomaly';
`,
	// 16: give devices back the traffic captured before they had names.
	//
	// Patrol tags a flow from another machine `lan-<address>`, because a packet
	// carries no identity beyond an address, and nothing ever completed that
	// sentence. On this network a printer had 2,168 captured flows filed under
	// `lan-192.168.68.58` while its actual Roster entry had none: one machine
	// living as two, invisible to its own Rap Sheet and a stranger to every rule
	// that groups by device. Ten of the twelve placeholders here resolve to a
	// device the Roster already knew, two of them link-local addresses belonging
	// to devices that had split part of their own traffic away from themselves.
	//
	// writeAddress now adopts these as soon as an address is tied to a device,
	// and WriteFlows resolves them before writing. This repairs what was written
	// before either existed.
	//
	// `lan-0.0.0.0` is deleted rather than resolved. A DHCP client asking for its
	// first lease sends from the unspecified address, which is not a device and
	// can never become one, so the placeholder would match no address discovery
	// could ever learn. Only the attribution is cleared; the flow itself stays,
	// and falls back to the address join like any other unattributed traffic.
	`
UPDATE flows SET device_id = (
  SELECT a.device_id FROM device_addresses a
  WHERE 'lan-' || a.ip = flows.device_id
)
WHERE device_id LIKE 'lan-%'
  AND EXISTS (
    SELECT 1 FROM device_addresses a WHERE 'lan-' || a.ip = flows.device_id
  );

UPDATE flows SET device_id = '' WHERE device_id = 'lan-0.0.0.0';
`,
	// 17: a pairing ledger that outlives the pairing.
	//
	// Unpairing deletes the peer and everything it ever reported, which is right
	// for the operator's decision to stop trusting a machine, and it means that
	// afterwards nothing on the system can answer "was this ever shared with
	// anyone, and when".
	//
	// That question matters most to the person least likely to have set the
	// software up. LAN Sheriff cannot stop somebody with physical access from
	// pairing a machine with their own; nothing running on that machine can. What
	// it can do is refuse to forget, so somebody who becomes suspicious of their
	// own computer gets an answer rather than a clean slate.
	//
	// Append-only by convention rather than by trigger. A trigger would be
	// theatre, since anyone able to drop the trigger can drop the table; this
	// raises the effort from "click unpair" to "know the schema and edit the
	// database", which is the honest limit of what local storage offers.
	`
CREATE TABLE IF NOT EXISTS pairing_log (
  id      INTEGER PRIMARY KEY,
  ts      INTEGER NOT NULL,
  peer_id TEXT NOT NULL,
  label   TEXT,
  -- 'paired' or 'unpaired'.
  event   TEXT NOT NULL,
  addr    TEXT
);
CREATE INDEX IF NOT EXISTS idx_pairing_log_ts ON pairing_log(ts);
`,
}
