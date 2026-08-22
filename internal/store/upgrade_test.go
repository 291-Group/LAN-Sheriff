package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Upgrading an existing database, which is what every test until now failed to
// cover.
//
// Every other test in this package starts from Open() on an empty file, so the
// migration list runs from scratch and produces a correct schema by definition.
// That is not what a user has. A user has a database written by an older build,
// and the only thing that touches it is the *tail* of the migration list.
//
// The distinction is not academic. A migration was once edited in place rather
// than appended to, so upgraded databases kept an older column layout while fresh
// ones did not. Flow writes failed against a column that was not there, for ten
// hours, and the entire suite stayed green throughout, because not one test ever
// opened a database it had not just created.

// openLegacy builds a database at the pre-optimization schema and opens it,
// which runs whatever migrations have been appended since.
func openLegacy(t *testing.T, seed func(*sql.DB)) (*Store, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("create legacy database: %v", err)
	}
	schema, err := os.ReadFile("testdata/schema_v2_legacy.sql")
	if err != nil {
		t.Fatalf("read legacy schema: %v", err)
	}
	if _, err := raw.Exec(string(schema)); err != nil {
		t.Fatalf("apply legacy schema: %v", err)
	}
	if seed != nil {
		seed(raw)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

// The bug exactly: an old database must end up writable by the current code.
func TestUpgradeFromLegacySchemaAcceptsWrites(t *testing.T) {
	const seeded = 3
	s, _ := openLegacy(t, func(db *sql.DB) {
		now := time.Now().Add(-24 * time.Hour).Unix()
		for i := 0; i < seeded; i++ {
			if _, err := db.Exec(`
INSERT INTO flows (flow_key, ts_start, ts_last, src_ip, src_port, dst_ip, dst_port, proto, active)
VALUES (?, ?, ?, '192.168.1.10', ?, '93.184.216.34', 443, 'tcp', 0)`,
				"legacy-key-", now, now, 40000+i); err != nil {
				// A duplicate flow_key would mean the seed is wrong, not the code.
				db.Exec(`INSERT INTO flows (flow_key, ts_start, ts_last, src_ip, dst_ip, proto, active)
VALUES (?, ?, ?, '192.168.1.10', '93.184.216.34', 'tcp', 0)`,
					"legacy-"+string(rune('a'+i)), now, now)
			}
		}
	})

	ctx := context.Background()
	before := countRows(t, s, "flows")
	if before == 0 {
		t.Fatal("the upgrade discarded every historical flow")
	}

	// The write that failed silently in the field.
	now := time.Now()
	if err := s.WriteFlows(ctx, []types.Flow{{
		Proto: "tcp", SrcIP: "192.168.1.10", SrcPort: 51000,
		DstIP: "1.1.1.1", DstPort: 443, Direction: "out",
		TSStart: now, TSLast: now, Active: true,
	}}); err != nil {
		t.Fatalf("an upgraded database rejected a flow write: %v", err)
	}
	if after := countRows(t, s, "flows"); after != before+1 {
		t.Errorf("flow count %d -> %d, want %d", before, after, before+1)
	}
}

// The upgrade must not lose what the user already collected.
func TestUpgradePreservesHistory(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	s, _ := openLegacy(t, func(db *sql.DB) {
		if _, err := db.Exec(`
INSERT INTO flows (flow_key, ts_start, ts_last, src_ip, src_port, dst_ip, dst_port, proto, bytes_out, bytes_in, active, direction)
VALUES ('kept', ?, ?, '10.0.0.5', 1234, '8.8.8.8', 53, 'udp', 999, 111, 0, 'out')`,
			old.Unix(), old.Unix()); err != nil {
			t.Fatalf("seed: %v", err)
		}
	})

	var (
		src, dst, proto, dir string
		out, in              int64
		tsLast               int64
	)
	err := s.db.QueryRow(`
SELECT src_ip, dst_ip, proto, direction, bytes_out, bytes_in, ts_last
FROM flows WHERE dst_ip = '8.8.8.8'`).Scan(&src, &dst, &proto, &dir, &out, &in, &tsLast)
	if err != nil {
		t.Fatalf("the historical flow did not survive the upgrade: %v", err)
	}
	if src != "10.0.0.5" || proto != "udp" || out != 999 || in != 111 || dir != "out" {
		t.Errorf("fields altered by the upgrade: src=%s proto=%s out=%d in=%d dir=%s", src, proto, out, in, dir)
	}
	if tsLast != old.Unix() {
		t.Errorf("ts_last = %d, want %d", tsLast, old.Unix())
	}
}

// Identity keys must be unique after the rebuild, or the deduplication that
// flow_hash exists for stops working.
func TestUpgradeLeavesFlowHashesUnique(t *testing.T) {
	s, _ := openLegacy(t, func(db *sql.DB) {
		now := time.Now().Unix()
		for i, k := range []string{"a", "b", "c", "d"} {
			db.Exec(`INSERT INTO flows (flow_key, ts_start, ts_last, src_ip, dst_ip, proto, active)
VALUES (?, ?, ?, '10.0.0.1', '10.0.0.2', 'tcp', 0)`, k, now-int64(i), now)
		}
	})

	var total, distinct int
	s.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT flow_hash) FROM flows`).Scan(&total, &distinct)
	if total != distinct {
		t.Errorf("%d rows share only %d distinct hashes", total, distinct)
	}
}

// Reopening must be a no-op. A migration that is not idempotent across restarts
// would corrupt or wipe data on the second launch rather than the first, which is
// far harder to attribute.
func TestUpgradeIsStableAcrossReopen(t *testing.T) {
	s, path := openLegacy(t, func(db *sql.DB) {
		now := time.Now().Unix()
		db.Exec(`INSERT INTO flows (flow_key, ts_start, ts_last, src_ip, dst_ip, proto, active)
VALUES ('once', ?, ?, '10.0.0.1', '10.0.0.2', 'tcp', 0)`, now, now)
	})
	first := countRows(t, s, "flows")
	s.Close()

	for i := 0; i < 3; i++ {
		again, err := Open(path)
		if err != nil {
			t.Fatalf("reopen %d failed: %v", i+1, err)
		}
		if n := countRows(t, again, "flows"); n != first {
			t.Errorf("reopen %d changed the flow count: %d, want %d", i+1, n, first)
		}
		again.Close()
	}
}

// Everything the identity model needs must exist after an upgrade, not only
// after a fresh install.
func TestUpgradeCreatesDeviceIdentityTables(t *testing.T) {
	s, _ := openLegacy(t, nil)

	id, err := s.ObserveDevice(context.Background(), types.Sighting{
		MAC: "DC:A6:32:00:00:0D", IP: "192.168.68.52",
		Hostname: "raspberrypi", Source: "neighbour", SeenAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("an upgraded database cannot record a device: %v", err)
	}
	if id == "" {
		t.Fatal("no device was created")
	}
}

// The guard must be satisfied by the upgrade path, not only by a fresh install:
// checkSchema runs inside Open, so a failure here means Open itself would fail
// for every existing user after a release.
func TestUpgradeSatisfiesSchemaGuard(t *testing.T) {
	s, _ := openLegacy(t, nil)
	if err := s.checkSchema(); err != nil {
		t.Fatalf("an upgraded database does not satisfy the schema guard: %v", err)
	}
}

// A fresh install and an upgraded database must end up with the same schema.
// Any divergence means one of them is running against columns the other lacks,
// which is the class of fault this whole file exists for.
func TestUpgradedSchemaMatchesFreshInstall(t *testing.T) {
	upgraded, _ := openLegacy(t, nil)
	fresh := newTestStore(t)

	for _, table := range []string{"flows", "endpoints", "devices", "dns_events", "device_keys", "device_addresses", "device_services"} {
		a, err := upgraded.columns(table)
		if err != nil {
			t.Fatalf("inspect upgraded %s: %v", table, err)
		}
		b, err := fresh.columns(table)
		if err != nil {
			t.Fatalf("inspect fresh %s: %v", table, err)
		}
		for col := range b {
			if !a[col] {
				t.Errorf("%s.%s exists in a fresh install but not after an upgrade", table, col)
			}
		}
		for col := range a {
			if !b[col] {
				t.Errorf("%s.%s exists after an upgrade but not in a fresh install", table, col)
			}
		}
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// Migration 9 adds The Dispatch tables. An existing install must be able to
// pair and merge after upgrading, not only a fresh one, this is the same
// upgrade path that once left every user writing into columns that were not
// there.
func TestUpgradeCreatesDispatchTables(t *testing.T) {
	s, _ := openLegacy(t, nil)
	ctx := context.Background()

	if err := s.AddPeer(ctx, Peer{
		PeerID: "UPGRADED-PEER", PublicKey: []byte("k"), Label: "After upgrade",
	}); err != nil {
		t.Fatalf("an upgraded database cannot record a peer: %v", err)
	}

	hour := time.Now().Truncate(time.Hour).Unix()
	n, err := s.MergePeerSummaries(ctx, "UPGRADED-PEER", []PeerSummary{{
		Device: "laptop", Hour: hour, Org: "Cloudflare, Inc.",
		App: "Firefox", Proto: "tcp", Port: 443, Flows: 3,
	}}, time.Now())
	if err != nil {
		t.Fatalf("an upgraded database cannot merge peer summaries: %v", err)
	}
	if n != 1 {
		t.Errorf("merged %d buckets, want 1", n)
	}
}
