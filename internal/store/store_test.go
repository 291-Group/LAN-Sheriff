package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func flow(dst string, start time.Time, active bool) types.Flow {
	return types.Flow{
		TSStart: start, TSLast: start.Add(time.Minute),
		DeviceID: "self-test", Process: "Firefox", PID: 42,
		SrcIP: "192.168.1.5", SrcPort: 5000,
		DstIP: dst, DstPort: 443, Proto: types.ProtoTCP,
		BytesOut: 1000, BytesIn: 2000, Active: active,
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	s.Close()

	// Reopening an existing database must not try to rebuild it.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	var version int
	if err := s2.DB().QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != len(migrations) {
		t.Errorf("schema version = %d, want %d", version, len(migrations))
	}
}

func TestFlowUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	f := flow("93.184.216.34", now, true)
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	// The same flow seen again is an update, not a second row.
	f.TSLast = now.Add(5 * time.Minute)
	f.BytesOut = 5000
	f.Active = false
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatalf("WriteFlows (update): %v", err)
	}

	var count int
	var bytesOut uint64
	var active int
	err := s.DB().QueryRow(`SELECT COUNT(*), MAX(bytes_out), MAX(active) FROM flows`).
		Scan(&count, &bytesOut, &active)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("row count = %d, want 1 (the flow should be upserted)", count)
	}
	if bytesOut != 5000 {
		t.Errorf("bytes_out = %d, want 5000", bytesOut)
	}
	if active != 0 {
		t.Error("the flow should have been marked closed")
	}
}

func TestByteCountersNeverShrinkOnUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	f := flow("93.184.216.34", now, true)
	f.BytesOut = 9000
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}
	f.BytesOut = 10 // a source that restarted its counters
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	var bytesOut uint64
	if err := s.DB().QueryRow(`SELECT bytes_out FROM flows`).Scan(&bytesOut); err != nil {
		t.Fatalf("query: %v", err)
	}
	if bytesOut != 9000 {
		t.Errorf("bytes_out = %d, want 9000; a total must not go backwards", bytesOut)
	}
}

func TestEndpointEnrichmentLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	err := s.TouchEndpoints(ctx, map[string]EndpointSighting{
		"93.184.216.34": Sighting(false, now),
		"192.168.1.1":   Sighting(true, now),
	})
	if err != nil {
		t.Fatalf("TouchEndpoints: %v", err)
	}

	// Only external addresses are worth enriching.
	pending, err := s.PendingEnrichment(ctx, 10)
	if err != nil {
		t.Fatalf("PendingEnrichment: %v", err)
	}
	if len(pending) != 1 || pending[0] != "93.184.216.34" {
		t.Fatalf("pending = %v, want just the external address", pending)
	}

	if err := s.SaveEnrichment(ctx, types.Endpoint{
		IP: "93.184.216.34", Country: "US", CountryName: "United States",
		City: "Boston", Lat: 42.36, Lon: -71.06, ASN: 15133, Org: "Edgecast",
	}); err != nil {
		t.Fatalf("SaveEnrichment: %v", err)
	}

	// Enriched addresses drop out of the queue.
	pending, _ = s.PendingEnrichment(ctx, 10)
	if len(pending) != 0 {
		t.Errorf("pending after enrichment = %v, want empty", pending)
	}

	ep, err := s.Endpoint(ctx, "93.184.216.34")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if ep.Org != "Edgecast" || ep.Country != "US" || ep.City != "Boston" {
		t.Errorf("enrichment did not round-trip: %+v", ep)
	}
	if ep.EnrichedAt == nil {
		t.Error("enriched_at should be set")
	}
}

func TestRequeueUnresolved(t *testing.T) {
	// The self-healing path: endpoints resolved before the datasets landed come
	// back with nothing, and must be tried again rather than left blank forever.
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.TouchEndpoints(ctx, map[string]EndpointSighting{
		"93.184.216.34": Sighting(false, now),
		"1.1.1.1":       Sighting(false, now),
	})
	// One resolved properly, one came back empty.
	s.SaveEnrichment(ctx, types.Endpoint{IP: "93.184.216.34", Country: "US", Org: "Edgecast"})
	s.SaveEnrichment(ctx, types.Endpoint{IP: "1.1.1.1"})

	n, err := s.RequeueUnresolved(ctx)
	if err != nil {
		t.Fatalf("RequeueUnresolved: %v", err)
	}
	if n != 1 {
		t.Errorf("requeued %d, want 1", n)
	}

	pending, _ := s.PendingEnrichment(ctx, 10)
	if len(pending) != 1 || pending[0] != "1.1.1.1" {
		t.Errorf("pending = %v, want just the unresolved address", pending)
	}
}

func TestEgressExcludesInternalAndAggregates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.TouchEndpoints(ctx, map[string]EndpointSighting{
		"93.184.216.34": Sighting(false, now),
		"192.168.1.1":   Sighting(true, now),
	})
	s.SaveEnrichment(ctx, types.Endpoint{IP: "93.184.216.34", Country: "US", Org: "Edgecast", Lat: 42.36, Lon: -71.06})

	// Two flows to the same destination should aggregate into one row.
	f1 := flow("93.184.216.34", now, true)
	f2 := flow("93.184.216.34", now, true)
	f2.SrcPort = 5001
	f2.Process = "Google Chrome"
	internal := flow("192.168.1.1", now, true)

	if err := s.WriteFlows(ctx, []types.Flow{f1, f2, internal}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	rows, err := s.Egress(ctx, Filter{Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("Egress: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d egress rows, want 1 (internal destinations are not egress)", len(rows))
	}
	r := rows[0]
	if r.IP != "93.184.216.34" {
		t.Errorf("ip = %s", r.IP)
	}
	if r.Conns != 2 {
		t.Errorf("conns = %d, want 2", r.Conns)
	}
	if len(r.Processes) != 2 {
		t.Errorf("processes = %v, want both apps", r.Processes)
	}
	if r.Org != "Edgecast" {
		t.Errorf("enrichment should be joined in, got org %q", r.Org)
	}
}

func TestEgressTimeWindow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	old := now.Add(-48 * time.Hour)

	s.TouchEndpoints(ctx, map[string]EndpointSighting{"93.184.216.34": Sighting(false, now)})
	s.WriteFlows(ctx, []types.Flow{flow("93.184.216.34", old, false)})

	rows, _ := s.Egress(ctx, Filter{Since: now.Add(-time.Hour)})
	if len(rows) != 0 {
		t.Errorf("a flow from two days ago should be outside a one-hour window, got %d rows", len(rows))
	}

	rows, _ = s.Egress(ctx, Filter{Since: now.Add(-72 * time.Hour)})
	if len(rows) != 1 {
		t.Errorf("it should appear in a three-day window, got %d rows", len(rows))
	}
}

func TestPruneDropsExpiredRawData(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.TouchEndpoints(ctx, map[string]EndpointSighting{"93.184.216.34": Sighting(false, now)})
	s.WriteFlows(ctx, []types.Flow{
		flow("93.184.216.34", now.Add(-100*time.Hour), false), // beyond a 72h window
		flow("1.1.1.1", now, true),                            // current
	})

	st, err := s.Prune(ctx, Retention{Raw: 72 * time.Hour, Rollup: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if st.Flows != 1 {
		t.Errorf("pruned %d flows, want 1", st.Flows)
	}

	var remaining int
	s.DB().QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&remaining)
	if remaining != 1 {
		t.Errorf("%d flows left, want 1", remaining)
	}
}

func TestDeviceUpsertKeepsFirstSeen(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	first := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	later := time.Now().Truncate(time.Second)

	d := types.Device{
		ID: "self-abc", Hostname: "laptop", Trust: types.TrustDeputized,
		FirstSeen: first, LastSeen: first, Online: true, IsSelf: true,
	}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	d.LastSeen = later
	d.FirstSeen = later // a restart does not know the original first sighting
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	devices, err := s.Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(devices))
	}
	if !devices[0].FirstSeen.Equal(first) {
		t.Errorf("first_seen = %v, want the original %v", devices[0].FirstSeen, first)
	}
	if !devices[0].LastSeen.Equal(later) {
		t.Errorf("last_seen = %v, want %v", devices[0].LastSeen, later)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, ok, _ := s.Setting(ctx, "theme"); ok {
		t.Error("an unset setting should report missing")
	}
	if err := s.SetSetting(ctx, "theme", "light"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, ok, err := s.Setting(ctx, "theme")
	if err != nil || !ok || v != "light" {
		t.Errorf("Setting = %q, %v, %v", v, ok, err)
	}
	// Writing again replaces rather than duplicating.
	s.SetSetting(ctx, "theme", "dark")
	v, _, _ = s.Setting(ctx, "theme")
	if v != "dark" {
		t.Errorf("Setting after overwrite = %q, want dark", v)
	}
}

func TestFilterNarrowsEgress(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	s.TouchEndpoints(ctx, map[string]EndpointSighting{
		"93.184.216.34": Sighting(false, now),
		"1.1.1.1":       Sighting(false, now),
	})
	s.SaveEnrichment(ctx, types.Endpoint{IP: "93.184.216.34", Country: "US", Org: "Edgecast"})
	s.SaveEnrichment(ctx, types.Endpoint{IP: "1.1.1.1", Country: "AU", Org: "Cloudflare"})

	firefox := flow("93.184.216.34", now, true)
	chrome := flow("1.1.1.1", now, true)
	chrome.Process = "Google Chrome"
	chrome.SrcPort = 5001
	if err := s.WriteFlows(ctx, []types.Flow{firefox, chrome}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	cases := []struct {
		name   string
		filter Filter
		wantIP string
	}{
		{"by app", Filter{Process: "Firefox"}, "93.184.216.34"},
		{"by country", Filter{Country: "AU"}, "1.1.1.1"},
		{"by org", Filter{Org: "Cloudflare"}, "1.1.1.1"},
		{"by port", Filter{Port: 443}, ""}, // both match
		{"free text on org", Filter{Search: "edgec"}, "93.184.216.34"},
		{"free text on app", Filter{Search: "Chrome"}, "1.1.1.1"},
		{"free text on address", Filter{Search: "1.1.1."}, "1.1.1.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.filter.Since = now.Add(-time.Hour)
			rows, err := s.Egress(ctx, c.filter)
			if err != nil {
				t.Fatalf("Egress: %v", err)
			}
			if c.wantIP == "" {
				if len(rows) != 2 {
					t.Fatalf("got %d rows, want both", len(rows))
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1", len(rows))
			}
			if rows[0].IP != c.wantIP {
				t.Errorf("matched %s, want %s", rows[0].IP, c.wantIP)
			}
		})
	}
}

func TestRollupAggregatesCompleteHoursOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Hour)

	// Two flows in a completed hour, one in the current (incomplete) hour.
	past := now.Add(-2 * time.Hour)
	a := flow("93.184.216.34", past, false)
	b := flow("1.1.1.1", past, false)
	b.SrcPort = 5001
	current := flow("8.8.8.8", now.Add(10*time.Minute), true)
	current.SrcPort = 5002

	s.TouchEndpoints(ctx, map[string]EndpointSighting{
		"93.184.216.34": Sighting(false, past),
		"1.1.1.1":       Sighting(false, past),
		"8.8.8.8":       Sighting(false, now),
	})
	if err := s.WriteFlows(ctx, []types.Flow{a, b, current}); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	n, err := s.Rollup(ctx, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Rollup: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one bucket to be aggregated")
	}

	var conns int64
	err = s.DB().QueryRow(
		`SELECT COALESCE(SUM(conns),0) FROM rollups WHERE key_type = ?`, RollupEndpoint).Scan(&conns)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if conns != 2 {
		t.Errorf("rolled up %d connections, want 2 (the current hour must not be included)", conns)
	}

	// Running again must not double-count.
	if _, err := s.Rollup(ctx, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("second Rollup: %v", err)
	}
	s.DB().QueryRow(`SELECT COALESCE(SUM(conns),0) FROM rollups WHERE key_type = ?`,
		RollupEndpoint).Scan(&conns)
	if conns != 2 {
		t.Errorf("after re-running, conns = %d, want 2", conns)
	}
}

func TestSearchAcrossKinds(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.TouchEndpoints(ctx, map[string]EndpointSighting{"93.184.216.34": Sighting(false, now)})
	s.SaveEnrichment(ctx, types.Endpoint{
		IP: "93.184.216.34", Country: "US", CountryName: "United States", Org: "Edgecast",
	})
	s.WriteFlows(ctx, []types.Flow{flow("93.184.216.34", now, true)})

	results, err := s.Search(ctx, "edgecast", 20)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	kinds := map[string]bool{}
	for _, r := range results {
		kinds[r.Kind] = true
	}
	if !kinds["endpoint"] || !kinds["org"] {
		t.Errorf("expected endpoint and org hits, got %+v", results)
	}

	// An application name should be findable too.
	results, _ = s.Search(ctx, "Firefox", 20)
	if len(results) == 0 {
		t.Error("expected the owning application to be searchable")
	}
}

func TestWipeClearsObservationsButKeepsSelf(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.UpsertDevice(ctx, types.Device{
		ID: "self-abc", Hostname: "laptop", Trust: types.TrustDeputized,
		FirstSeen: now, LastSeen: now, IsSelf: true,
	})
	s.TouchEndpoints(ctx, map[string]EndpointSighting{"93.184.216.34": Sighting(false, now)})
	s.WriteFlows(ctx, []types.Flow{flow("93.184.216.34", now, true)})

	if err := s.Wipe(ctx); err != nil {
		t.Fatalf("Wipe: %v", err)
	}

	for _, table := range []string{"flows", "endpoints", "rollups"} {
		var n int
		s.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Errorf("%s still has %d rows after wipe", table, n)
		}
	}
	// This host is identity, not an observation, and should survive.
	devices, _ := s.Devices(ctx)
	if len(devices) != 1 {
		t.Errorf("got %d devices after wipe, want this host to remain", len(devices))
	}
}

// The database is the most sensitive thing LAN Sheriff holds: a searchable
// record of which servers every device on the network contacted, and when. The
// threat model names it as the top asset.
//
// SQLite creates it with the process umask (normally 0644) and it was
// protected only by the data directory, which is created at 0700. But MkdirAll
// sets a mode only when it *creates* the directory. A packaged install writing
// into an existing /var/lib path, a mounted Docker volume, or a user passing
// --data-dir ~/Documents all leave the directory's own permissions in place and
// the database world-readable inside it.
func TestDatabaseIsNotReadableByOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not the access control model on Windows")
	}

	// A data directory that already exists and is world-traversable, which is
	// the case the directory mode does not cover.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Force the WAL and shared-memory files into existence: -wal holds recent
	// writes and leaks exactly the same data as the main file.
	if _, err := s.db.Exec(
		`INSERT INTO endpoints (ip, org, first_seen, last_seen, is_internal)
		 VALUES ('203.0.113.1', 'Example Org', 1, 2, 0)`); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"test.db", "test.db-wal", "test.db-shm"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue // SQLite creates these on demand
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s is mode %04o, readable beyond the owning account", name, mode)
		}
	}
}

// A capped Egress result used to be indistinguishable from a complete one, so
// the Watchtower presented the cap as the number of destinations seen. That is
// wrong for exactly the people with the most to look at.
func TestEgressReportsWhatTheLimitCut(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	// Twelve external destinations, all inside the window. Documentation range,
	// so nothing here resolves to anything real.
	sightings := map[string]EndpointSighting{}
	var flows []types.Flow
	for i := 1; i <= 12; i++ {
		ip := "203.0.113." + itoa(i)
		sightings[ip] = Sighting(false, now)
		flows = append(flows, flow(ip, now, true))
	}
	s.TouchEndpoints(ctx, sightings)
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatalf("WriteFlows: %v", err)
	}

	for _, c := range []struct {
		limit    int
		wantRows int
		wantCut  int
	}{
		{limit: 5, wantRows: 5, wantCut: 7},
		{limit: 12, wantRows: 12, wantCut: 0}, // exactly full, nothing beyond it
		{limit: 50, wantRows: 12, wantCut: 0}, // room to spare
	} {
		f := Filter{Since: now.Add(-time.Hour), Limit: c.limit}
		rows, err := s.Egress(ctx, f)
		if err != nil {
			t.Fatalf("limit %d: Egress: %v", c.limit, err)
		}
		if len(rows) != c.wantRows {
			t.Errorf("limit %d: got %d rows, want %d", c.limit, len(rows), c.wantRows)
		}
		cut, err := s.EgressOmitted(ctx, f, len(rows))
		if err != nil {
			t.Fatalf("limit %d: EgressOmitted: %v", c.limit, err)
		}
		if cut != c.wantCut {
			t.Errorf("limit %d: reported %d omitted, want %d", c.limit, cut, c.wantCut)
		}
	}
}
