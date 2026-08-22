// Package store is the bounded, self-pruning embedded database every view
// reads from. It uses SQLite through a pure-Go driver so the default build
// stays cgo-free.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"

	_ "modernc.org/sqlite"
)

// Store is the database handle.
type Store struct {
	db   *sql.DB
	path string

	// OnFinding is called once for each genuinely new finding, never for one
	// that was merely seen again. Optional; nil means nothing is announced.
	//
	// Set by the caller so the store does not need to know that notifications
	// exist.
	OnFinding func(rule, subject string, score float64)
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}

	// WAL keeps the reader (API queries) from blocking the writer (ingest).
	// busy_timeout covers the pruner overlapping a write burst.
	//
	// **_txlock=immediate is not optional here.** Several write paths read and
	// then write inside one transaction, ObserveDevice resolves a device before
	// it updates it, which is the whole point of it. A deferred transaction takes
	// its read snapshot at the first SELECT and only asks for the write lock
	// later, so if another connection commits in between, SQLite fails the
	// upgrade with SQLITE_BUSY_SNAPSHOT (517). **busy_timeout does not help with
	// that one**: it is not contention that will clear if you wait, it is a
	// snapshot that has already gone stale, and the only remedy is to retry the
	// whole transaction.
	//
	// Deputy Mode never wrote hard enough to trigger it. The first minutes of
	// Patrol Mode did, and the symptom was device sightings being dropped,
	// silent data loss in the Roster, reported only as a warning nobody would
	// read. Taking the write lock up front removes the race rather than racing.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// Reads still run concurrently under WAL; writes serialize on the immediate
	// lock, which is what SQLite does anyway, now without failing to do it.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	// **The database is the most sensitive thing this product holds**, a
	// searchable record of who every device talked to, and when. The threat
	// model names it as the top asset, and yet SQLite creates it with the
	// process umask, which is normally 0644: readable by every account on the
	// machine.
	//
	// It was protected only by the data directory, which MkdirAll creates at
	// 0700, but only when it *creates* it. Point --data-dir at a directory that
	// already exists, which is what a packaged install or a mounted volume does,
	// and the directory keeps its own permissions while the database sits inside
	// it world-readable. Verified: a 0755 data directory yields a 0644 database.
	//
	// The WAL and shared-memory files carry the same data and need the same
	// treatment; the -wal file in particular holds recent writes.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}

	// **After Ping and after migrating, not before.** `sql.Open` is lazy, it
	// validates the DSN and connects nothing, so calling this earlier chmod'd a
	// file that did not exist yet, the "not found" was skipped as benign, and
	// SQLite then created it at 0644 anyway. The first attempt did exactly that
	// and the test caught it. The -wal and -shm files appear later still, once
	// WAL mode is set and something is written.
	if err := restrictPerms(path); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// Again after migrating: the first writes create -wal and -shm, and those
	// carry the same data as the database itself.
	if err := restrictPerms(path); err != nil {
		db.Close()
		return nil, err
	}
	// Migrations reporting success is not the same as the schema being right:
	// an already-recorded migration is skipped, so a database can be "fully
	// migrated" and still have the wrong columns.
	if err := s.checkSchema(); err != nil {
		db.Close()
		return nil, err
	}
	// Establishes when this install began observing, which is what separates the
	// initial census of a network from an arrival on it.
	if err := s.markBaseline(time.Now()); err != nil {
		db.Close()
		return nil, err
	}
	// Query statistics, once, before anything is served.
	//
	// The pruner refreshes these on its own schedule, but its first pass is
	// hours away, and an instance restarted over an existing database would
	// spend that time planning the map query as though the database were empty.
	// That is the case this matters in: a fresh install has nothing to analyse
	// and this does nothing, while an install with a year of history gets the
	// plans that history deserves before it answers its first request.
	s.analyzeIfNeverAnalysed(context.Background())
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("migrations table: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for i := current; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for callers that need one-off queries.
func (s *Store) DB() *sql.DB { return s.db }

// Path is the database file location.
func (s *Store) Path() string { return s.path }

// flowHash is the stable identity of a flow row across restarts. The
// normalizer's in-memory IDs are per-process, so persistence needs its own key.
//
// A 64-bit hash rather than the text it derives from, because the text and its
// unique index measured at 42% of the whole database. The collision risk is the
// trade being made, and it is negligible: across the ~2.4 million rows a
// 512 MiB database holds, the birthday bound puts it near one in six million,
// and the consequence would be two flows merging into one row rather than
// anything unsafe.
func flowHash(f types.Flow) int64 {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s:%d|%s:%d|%d",
		f.DeviceID, f.Proto, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.TSStart.Unix())
	return int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
}

// direction defaults a flow with no recorded direction to outbound, which is
// what every flow written before the column existed was.
func direction(f types.Flow) types.Direction {
	if f.Direction == "" {
		return types.DirOut
	}
	return f.Direction
}

// WriteFlows upserts a batch of flows in a single transaction.
func (s *Store) WriteFlows(ctx context.Context, flows []types.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO flows (flow_hash, ts_start, ts_last, device_id, process, pid,
                   src_ip, src_port, dst_ip, dst_port, proto, bytes_out, bytes_in, active, direction,
                   established)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(flow_hash) DO UPDATE SET
  ts_last   = excluded.ts_last,
  bytes_out = MAX(flows.bytes_out, excluded.bytes_out),
  bytes_in  = MAX(flows.bytes_in, excluded.bytes_in),
  active    = excluded.active,
  process   = COALESCE(NULLIF(excluded.process, ''), flows.process),
  pid       = COALESCE(NULLIF(excluded.pid, 0), flows.pid),
  -- Once established, always established: a connection that has since closed
  -- still proved something was listening.
  established = MAX(flows.established, excluded.established)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Resolve placeholders before writing, so a device already on the Roster
	// never acquires a second identity in the first place. adoptPlaceholderFlows
	// repairs what was written before discovery knew the address; this stops most
	// of it being written at all.
	known, err := resolvePlaceholders(ctx, tx, flows)
	if err != nil {
		return err
	}

	for _, f := range flows {
		if id, ok := known[f.DeviceID]; ok {
			f.DeviceID = id
		}
		if _, err := stmt.ExecContext(ctx,
			flowHash(f), f.TSStart.Unix(), f.TSLast.Unix(), f.DeviceID, f.Process, f.PID,
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, string(f.Proto),
			f.BytesOut, f.BytesIn, boolInt(f.Active), string(direction(f)),
			boolInt(f.Established),
		); err != nil {
			return fmt.Errorf("write flow: %w", err)
		}
	}
	return tx.Commit()
}

// resolvePlaceholders maps `lan-<address>` device ids in a batch to the real
// devices holding those addresses.
//
// One query for the whole batch rather than one per flow: a busy vantage point
// writes thousands of flows a pass, and this runs on every one of them.
func resolvePlaceholders(ctx context.Context, tx *sql.Tx, flows []types.Flow) (map[string]string, error) {
	ips := map[string]string{} // address -> placeholder id
	for _, f := range flows {
		if strings.HasPrefix(f.DeviceID, "lan-") {
			ips[strings.TrimPrefix(f.DeviceID, "lan-")] = f.DeviceID
		}
	}
	if len(ips) == 0 {
		return nil, nil
	}

	args := make([]any, 0, len(ips))
	for ip := range ips {
		args = append(args, ip)
	}
	q := `SELECT ip, device_id FROM device_addresses WHERE ip IN (?` +
		strings.Repeat(",?", len(args)-1) + `)`
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("resolve placeholders: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var ip, id string
		if err := rows.Scan(&ip, &id); err != nil {
			return nil, err
		}
		if ph, ok := ips[ip]; ok && id != "" && id != ph {
			out[ph] = id
		}
	}
	return out, rows.Err()
}

// TouchEndpoints records that these addresses were seen, creating rows for any
// that are new so the enricher has something to work on.
func (s *Store) TouchEndpoints(ctx context.Context, seen map[string]EndpointSighting) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO endpoints (ip, is_internal, first_seen, last_seen)
VALUES (?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET last_seen = MAX(endpoints.last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for ip, sight := range seen {
		if _, err := stmt.ExecContext(ctx, ip, boolInt(sight.Internal),
			sight.Seen.Unix(), sight.Seen.Unix()); err != nil {
			return fmt.Errorf("touch endpoint: %w", err)
		}
	}
	return tx.Commit()
}

// EndpointSighting is one observation of an address.
type EndpointSighting struct {
	Internal bool
	Seen     time.Time
}

// Sighting builds an endpoint sighting.
func Sighting(internal bool, seen time.Time) EndpointSighting {
	return EndpointSighting{Internal: internal, Seen: seen}
}

// PendingEnrichment returns external addresses that have never been enriched,
// most recently seen first so the map fills in with what the user is looking at.
func (s *Store) PendingEnrichment(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ip FROM endpoints
WHERE enriched_at IS NULL AND is_internal = 0
ORDER BY last_seen DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// RequeueUnresolved clears the enrichment stamp on endpoints that came back
// with nothing useful, so they are tried again.
//
// This exists because the location databases are fetched in the background:
// endpoints observed in the first seconds of a first run get resolved against a
// set that has not landed yet. Without this they would stay blank forever, and
// the map would be permanently half-empty for every new install.
func (s *Store) RequeueUnresolved(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE endpoints SET enriched_at = NULL
WHERE is_internal = 0 AND enriched_at IS NOT NULL
  AND (country IS NULL OR country = '' OR org IS NULL OR org = '')`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SaveEnrichment stores the enrichment for one endpoint.
func (s *Store) SaveEnrichment(ctx context.Context, e types.Endpoint) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE endpoints SET rdns = ?, asn = ?, org = ?, country = ?, country_name = ?,
                     city = ?, lat = ?, lon = ?, enriched_at = ?
WHERE ip = ?`,
		e.RDNS, e.ASN, e.Org, e.Country, e.CountryName, e.City, e.Lat, e.Lon,
		time.Now().Unix(), e.IP)
	return err
}

// Endpoint reads one endpoint with its enrichment.
func (s *Store) Endpoint(ctx context.Context, ip string) (types.Endpoint, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT ip, COALESCE(rdns,''), COALESCE(asn,0), COALESCE(org,''), COALESCE(country,''),
       COALESCE(country_name,''), COALESCE(city,''), COALESCE(lat,0), COALESCE(lon,0),
       is_internal, first_seen, last_seen, enriched_at
FROM endpoints WHERE ip = ?`, ip)
	return scanEndpoint(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(r rowScanner) (types.Endpoint, error) {
	var (
		e           types.Endpoint
		internal    int
		first, last int64
		enriched    sql.NullInt64
	)
	err := r.Scan(&e.IP, &e.RDNS, &e.ASN, &e.Org, &e.Country, &e.CountryName, &e.City,
		&e.Lat, &e.Lon, &internal, &first, &last, &enriched)
	if err != nil {
		return types.Endpoint{}, err
	}
	e.IsInternal = internal != 0
	e.FirstSeen = time.Unix(first, 0)
	e.LastSeen = time.Unix(last, 0)
	if enriched.Valid {
		t := time.Unix(enriched.Int64, 0)
		e.EnrichedAt = &t
	}
	return e, nil
}

// EgressRow is one external destination, aggregated across its flows: what the
// Watchtower draws.
type EgressRow struct {
	types.Endpoint
	Conns     int      `json:"conns"`
	BytesOut  uint64   `json:"bytes_out"`
	BytesIn   uint64   `json:"bytes_in"`
	Processes []string `json:"processes,omitempty"`
	Devices   []string `json:"devices,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Active    bool     `json:"active"`
	LastFlow  int64    `json:"last_flow"`
}

// Egress returns external destinations with their aggregated traffic: what the
// Watchtower draws.
// EgressOmitted reports how many destinations matched the filter beyond the
// rows Egress returned.
//
// Egress applies its limit in SQL, so a full result is indistinguishable from a
// truncated one: the caller receives exactly `limit` rows either way. The
// Watchtower then stated that number as "N seen in this period", which stops
// being true the moment somebody has more destinations than the cap, and says
// so most confidently to the people watching the busiest networks. The Precinct
// Map has always reported what it folded away; this is the same honesty for the
// list beside it.
//
// Returns without querying unless the result came back full, so the ordinary
// case where nothing was cut pays nothing for the check.
func (s *Store) EgressOmitted(ctx context.Context, f Filter, shown int) (int, error) {
	if shown < f.limit() {
		return 0, nil
	}
	where, args := f.where("f", "e")
	where = append(where, "e.is_internal = 0")
	// Grouped first, then counted: the join multiplies each destination by its
	// flows, so counting rows here would report connections and call them
	// destinations. No liveness placeholder, because unlike Egress this selects
	// nothing that needs one.
	q := `
SELECT COUNT(*) FROM (
  SELECT e.ip
  FROM flows f
  JOIN endpoints e ON e.ip = f.dst_ip
  WHERE ` + strings.Join(where, " AND ") + `
  GROUP BY e.ip)`
	var total int
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	if total <= shown {
		return 0, nil
	}
	return total - shown, nil
}

func (s *Store) Egress(ctx context.Context, f Filter) ([]EgressRow, error) {
	where, args := f.where("f", "e")
	where = append(where, "e.is_internal = 0")
	// **Prepended, not appended.** The liveness placeholder is in the SELECT
	// list, which the driver binds before anything in the WHERE clause, so
	// adding it at the end would silently shift every filter by one and quietly
	// return the wrong rows rather than failing.
	args = append([]any{time.Now().Add(-ActiveWithin).Unix()}, args...)
	args = append(args, f.limit())

	q := `
SELECT e.ip, COALESCE(e.rdns,''), COALESCE(e.asn,0), COALESCE(e.org,''), COALESCE(e.country,''),
       COALESCE(e.country_name,''), COALESCE(e.city,''), COALESCE(e.lat,0), COALESCE(e.lon,0),
       e.is_internal, e.first_seen, e.last_seen, e.enriched_at,
       COUNT(f.id), COALESCE(SUM(f.bytes_out),0), COALESCE(SUM(f.bytes_in),0),
       -- Live means recently seen, not "was open once". The stored flag is
       -- never cleared, so MAX(f.active) alone painted 91% of the map as live
       -- traffic, including destinations last touched days earlier. See
       -- ActiveWithin.
       MAX(f.active AND f.ts_last >= ?), MAX(f.ts_last),
       COALESCE(GROUP_CONCAT(DISTINCT f.process), ''),
       COALESCE(GROUP_CONCAT(DISTINCT f.device_id), ''),
       COALESCE(GROUP_CONCAT(DISTINCT f.dst_port), '')
FROM flows f
JOIN endpoints e ON e.ip = f.dst_ip
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY e.ip
ORDER BY MAX(f.ts_last) DESC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EgressRow
	for rows.Next() {
		var (
			r                     EgressRow
			internal, active      int
			first, last           int64
			enriched              sql.NullInt64
			procs, devices, ports string
		)
		if err := rows.Scan(&r.IP, &r.RDNS, &r.ASN, &r.Org, &r.Country, &r.CountryName,
			&r.City, &r.Lat, &r.Lon, &internal, &first, &last, &enriched,
			&r.Conns, &r.BytesOut, &r.BytesIn, &active, &r.LastFlow,
			&procs, &devices, &ports); err != nil {
			return nil, err
		}
		r.IsInternal = internal != 0
		r.Active = active != 0
		r.FirstSeen = time.Unix(first, 0)
		r.LastSeen = time.Unix(last, 0)
		if enriched.Valid {
			t := time.Unix(enriched.Int64, 0)
			r.EnrichedAt = &t
		}
		r.Processes = splitList(procs)
		r.Devices = splitList(devices)
		r.Ports = splitInts(ports)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Flows returns individual flow records, for export and for drilling into a
// single endpoint rather than the aggregate.
func (s *Store) Flows(ctx context.Context, f Filter) ([]types.Flow, error) {
	where, args := f.where("f", "e")
	args = append(args, f.limit())

	q := `
SELECT f.ts_start, f.ts_last, COALESCE(f.device_id,''), COALESCE(f.process,''),
       COALESCE(f.pid,0), f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.proto,
       f.bytes_out, f.bytes_in, f.active, f.direction
FROM flows f
LEFT JOIN endpoints e ON e.ip = f.dst_ip`
	if len(where) > 0 {
		q += "\nWHERE " + strings.Join(where, " AND ")
	}
	q += "\nORDER BY f.ts_last DESC\nLIMIT ?"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.Flow
	for rows.Next() {
		var (
			fl          types.Flow
			start, last int64
			active      int
		)
		if err := rows.Scan(&start, &last, &fl.DeviceID, &fl.Process, &fl.PID,
			&fl.SrcIP, &fl.SrcPort, &fl.DstIP, &fl.DstPort, &fl.Proto,
			&fl.BytesOut, &fl.BytesIn, &active, &fl.Direction); err != nil {
			return nil, err
		}
		fl.TSStart, fl.TSLast, fl.Active = time.Unix(start, 0), time.Unix(last, 0), active != 0
		out = append(out, fl)
	}
	return out, rows.Err()
}

// Search looks across endpoints, organizations, applications and countries at
// once, so the user can type "netflix" or "1.1.1.1" without choosing a category
// first.
func (s *Store) Search(ctx context.Context, term string, limit int) ([]SearchResult, error) {
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 20
	}
	like := "%" + term + "%"

	q := `
SELECT 'endpoint', e.ip,
       CASE WHEN e.org != '' THEN e.org WHEN e.rdns != '' THEN e.rdns ELSE e.ip END,
       COALESCE(e.country_name, ''), COUNT(f.id) AS n
FROM endpoints e LEFT JOIN flows f ON f.dst_ip = e.ip
WHERE e.is_internal = 0 AND (e.ip LIKE ? OR e.rdns LIKE ? OR e.org LIKE ?)
GROUP BY e.ip

UNION ALL
SELECT 'org', e.org, e.org, '', COUNT(f.id)
FROM endpoints e JOIN flows f ON f.dst_ip = e.ip
WHERE e.org != '' AND e.org LIKE ?
GROUP BY e.org

UNION ALL
SELECT 'process', f.process, f.process, '', COUNT(*)
FROM flows f
WHERE f.process != '' AND f.process LIKE ?
GROUP BY f.process

UNION ALL
SELECT 'country', e.country, COALESCE(NULLIF(e.country_name,''), e.country), '', COUNT(f.id)
FROM endpoints e JOIN flows f ON f.dst_ip = e.ip
WHERE e.country != '' AND (e.country LIKE ? OR e.country_name LIKE ?)
GROUP BY e.country

ORDER BY n DESC
LIMIT ?`

	rows, err := s.db.QueryContext(ctx, q, like, like, like, like, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.Kind, &r.Key, &r.Label, &r.Detail, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Wipe deletes every observation, leaving settings and the schema intact.
// It backs the one-click wipe the privacy posture promises.
func (s *Store) Wipe(ctx context.Context) error {
	for _, t := range []string{"flows", "dns_events", "endpoints", "rollups", "findings"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+t); err != nil {
			return fmt.Errorf("wipe %s: %w", t, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE is_self = 0`); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, rollupCursorKey, "0"); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "VACUUM")
	return err
}

// UpsertDevice inserts or refreshes a device.
func (s *Store) UpsertDevice(ctx context.Context, d types.Device) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO devices (id, mac, ip, hostname, vendor, device_type, label, trust,
                     first_seen, last_seen, online, suspicion, is_self)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  ip        = COALESCE(NULLIF(excluded.ip, ''), devices.ip),
  hostname  = COALESCE(NULLIF(excluded.hostname, ''), devices.hostname),
  last_seen = MAX(devices.last_seen, excluded.last_seen),
  online    = excluded.online`,
		d.ID, d.MAC, d.IP, d.Hostname, d.Vendor, d.DeviceType, d.Label, d.Trust,
		d.FirstSeen.Unix(), d.LastSeen.Unix(), boolInt(d.Online), d.Suspicion, boolInt(d.IsSelf))
	return err
}

// Devices returns the roster.
func (s *Store) Devices(ctx context.Context) ([]types.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, COALESCE(mac,''), COALESCE(ip,''), COALESCE(hostname,''), COALESCE(vendor,''),
       COALESCE(device_type,''), COALESCE(label,''), trust, first_seen, last_seen,
       online, suspicion, is_self,
       COALESCE(name,''), COALESCE(model,''), mac_randomized, COALESCE(notes,''),
       COALESCE(type_reason,''), type_locked
FROM devices ORDER BY is_self DESC, last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.Device
	for rows.Next() {
		var (
			d                          types.Device
			first, last                int64
			online, isSelf, randomized int
			typeLocked                 int
		)
		if err := rows.Scan(&d.ID, &d.MAC, &d.IP, &d.Hostname, &d.Vendor, &d.DeviceType,
			&d.Label, &d.Trust, &first, &last, &online, &d.Suspicion, &isSelf,
			&d.Name, &d.Model, &randomized, &d.Notes,
			&d.TypeReason, &typeLocked); err != nil {
			return nil, err
		}
		d.FirstSeen, d.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		d.Online, d.IsSelf, d.MACRandomized = online != 0, isSelf != 0, randomized != 0
		d.TypeLocked = typeLocked != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// Summary is the headline count set.
type Summary struct {
	Flows        int64   `json:"flows"`
	ActiveFlows  int64   `json:"active_flows"`
	Endpoints    int64   `json:"endpoints"`
	Countries    int64   `json:"countries"`
	Devices      int64   `json:"devices"`
	Inbound      int64   `json:"inbound"`
	DNSEvents    int64   `json:"dns_events"`
	TopOrgs      []Count `json:"top_orgs"`
	TopCountries []Count `json:"top_countries"`
	TopProcesses []Count `json:"top_processes"`
	DBBytes      int64   `json:"db_bytes"`
}

// Count is a label with a tally.
type Count struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	N     int64  `json:"n"`
}

// ActiveWithin is how recently a flow must have been seen to count as live.
//
// **The stored `active` flag is set and never cleared.** A capture source marks
// a flow active while it can see it, and when the connection closes the flow
// simply stops being reported: nothing goes back and writes active = 0. So the
// flag means "was open at some point", and reading it as "is open now" produced
// a headline that said 176,838 live connections on a laptop where 238 flows had
// been seen in the last minute, and drew 91% of the world map as live traffic
// including destinations last touched three days earlier.
//
// Recency is the honest signal, because ts_last is updated every time a source
// sees the flow. Two minutes against a two-second poll is sixty chances to be
// counted, so an open connection is not going to be missed, and a closed one
// drops off quickly enough that the number means what a reader thinks it means.
//
// Deliberately shorter than OfflineAfter, which is five minutes for a device. A
// device that has said nothing for four minutes is very likely still on the
// network; a connection that has carried nothing for four minutes is very
// likely finished.
//
// The alternative was a background pass writing active = 0, as
// MarkStaleDevicesOffline does for devices. Deriving it at read time cannot
// drift, needs no migration, and corrects every existing database on the next
// query rather than only after a pass has run.
const ActiveWithin = 2 * time.Minute

// Summary computes the dashboard headline numbers over a time window.
func (s *Store) Summary(ctx context.Context, since time.Time) (Summary, error) {
	var sum Summary
	sinceUnix := since.Unix()

	liveSince := time.Now().Add(-ActiveWithin).Unix()
	row := s.db.QueryRowContext(ctx, `
SELECT (SELECT COUNT(*) FROM flows WHERE ts_last >= ?),
       (SELECT COUNT(*) FROM flows WHERE active = 1 AND ts_last >= ?),
       (SELECT COUNT(*) FROM devices),
       (SELECT COUNT(*) FROM dns_events WHERE ts >= ?),
       (SELECT COUNT(*) FROM flows WHERE direction = 'in' AND ts_last >= ?)`,
		sinceUnix, liveSince, sinceUnix, sinceUnix)
	if err := row.Scan(&sum.Flows, &sum.ActiveFlows,
		&sum.Devices, &sum.DNSEvents, &sum.Inbound); err != nil {
		return sum, err
	}

	// **Destinations counted through the flows, the way the Watchtower lists
	// them.**
	//
	// Counting the endpoints table directly answered a different question: it
	// returned every endpoint row whose last_seen fell in the window, which is
	// not the same as every destination something connected out to. The two
	// numbers sat beside each other on one screen and disagreed, 82 in the
	// status bar against 80 in the list under it.
	//
	// The gap was this machine's own global IPv6 addresses. They are the source
	// of outbound flows and the destination of none, and with no NAT to make
	// them look local they were filed as foreign. The pipeline no longer does
	// that, but a database written before the fix still holds them, and joining
	// here corrects those on the next query rather than only after a migration.
	//
	// Both numbers come from one pass. Asking separately cost twice as long on
	// an 80MB database for two scans of the same rows, 0.06s against 0.03s.
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COUNT(DISTINCT NULLIF(country, ''))
FROM (SELECT e.ip AS ip, e.country AS country
      FROM flows f JOIN endpoints e ON e.ip = f.dst_ip
      WHERE e.is_internal = 0 AND f.direction = 'out' AND f.ts_last >= ?
      GROUP BY e.ip)`, sinceUnix).Scan(&sum.Endpoints, &sum.Countries); err != nil {
		return sum, err
	}

	var err error
	if sum.TopOrgs, err = s.topBy(ctx, "e.org", "", sinceUnix); err != nil {
		return sum, err
	}
	if sum.TopCountries, err = s.topBy(ctx, "e.country", "e.country_name", sinceUnix); err != nil {
		return sum, err
	}
	if sum.TopProcesses, err = s.topBy(ctx, "f.process", "", sinceUnix); err != nil {
		return sum, err
	}
	if fi, err := os.Stat(s.path); err == nil {
		sum.DBBytes = fi.Size()
	}
	// **Never null for a collection.** A nil slice marshals as `null`, the
	// dashboard reads these as arrays, and an empty database therefore handed
	// the client three nulls where it expected lists. The Roster hit the same
	// thing and crashed outright; these happen not to be indexed today, which
	// makes them a trap rather than a bug, and a trap in the code path every
	// new install takes on its first second.
	if sum.TopOrgs == nil {
		sum.TopOrgs = []Count{}
	}
	if sum.TopCountries == nil {
		sum.TopCountries = []Count{}
	}
	if sum.TopProcesses == nil {
		sum.TopProcesses = []Count{}
	}

	return sum, nil
}

func (s *Store) topBy(ctx context.Context, keyExpr, labelExpr string, since int64) ([]Count, error) {
	label := "''"
	if labelExpr != "" {
		label = "COALESCE(MAX(" + labelExpr + "), '')"
	}
	q := `
SELECT ` + keyExpr + ` AS k, ` + label + `, COUNT(*) AS n
FROM flows f JOIN endpoints e ON e.ip = f.dst_ip
WHERE e.is_internal = 0 AND f.ts_last >= ? AND ` + keyExpr + ` IS NOT NULL AND ` + keyExpr + ` != ''
GROUP BY k ORDER BY n DESC LIMIT 10`

	rows, err := s.db.QueryContext(ctx, q, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Count
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Label, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Setting reads a persisted setting.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting writes a persisted setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// RecordShape reports what a stored database contains.
//
// For --offline, where nothing is capturing and the capability model would
// otherwise describe an absence. Advertising nothing was the first attempt and
// it was wrong in a way that mattered: the dashboard hid traffic volumes behind
// "needs Patrol mode" while the record it was reading held byte counts for
// every flow. Capabilities drive what the views are willing to render, so
// offline has to answer "what is in here", not "what is running".
type RecordShape struct {
	Flows      bool
	Bytes      bool
	Processes  bool
	DNS        bool
	Devices    bool
	OtherHosts bool
}

func (s *Store) RecordShape(ctx context.Context) (RecordShape, error) {
	var r RecordShape
	err := s.db.QueryRowContext(ctx, `
SELECT
  EXISTS(SELECT 1 FROM flows),
  EXISTS(SELECT 1 FROM flows WHERE bytes_out > 0 OR bytes_in > 0),
  EXISTS(SELECT 1 FROM flows WHERE COALESCE(process, '') != ''),
  EXISTS(SELECT 1 FROM dns_events),
  EXISTS(SELECT 1 FROM devices),
  (SELECT COUNT(DISTINCT device_id) FROM flows WHERE COALESCE(device_id, '') != '') > 1
`).Scan(&r.Flows, &r.Bytes, &r.Processes, &r.DNS, &r.Devices, &r.OtherHosts)
	return r, err
}

// WriteDNS records DNS observations.
func (s *Store) WriteDNS(ctx context.Context, events []types.DNSEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO dns_events (ts, device_id, process, qname, qtype, answers, resp_ms, flagged)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		answers, _ := json.Marshal(e.Answers)
		if _, err := stmt.ExecContext(ctx, e.TS.Unix(), e.DeviceID, e.Process,
			e.QName, e.QType, string(answers), e.RespMS, e.Flagged); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitInts(s string) []int {
	var out []int
	for _, p := range splitList(s) {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// restrictPerms makes the database readable only by the account running LAN
// Sheriff.
//
// Applied on every open rather than only at creation: a database restored from a
// backup, copied between machines, or created by an older build would otherwise
// keep whatever mode it arrived with. A missing sidecar file is not an error,
// SQLite creates -wal and -shm on demand, so they may legitimately not exist
// yet.
func restrictPerms(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("securing %s: %w", p, err)
		}
	}
	return nil
}
