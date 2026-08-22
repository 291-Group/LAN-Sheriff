package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// These benchmarks exist to answer one question with numbers rather than
// guesswork: are the retention defaults (72h of full
// detail, 512 MiB cap) actually safe on a Raspberry Pi with a busy network?
//
// Run with:
//   go test ./internal/store/ -run '^$' -bench . -benchtime 10000x

func benchFlows(n int, start time.Time) []types.Flow {
	flows := make([]types.Flow, n)
	for i := range flows {
		flows[i] = types.Flow{
			TSStart:  start.Add(time.Duration(i) * time.Millisecond),
			TSLast:   start.Add(time.Duration(i)*time.Millisecond + time.Second),
			DeviceID: "self-bench",
			Process:  fmt.Sprintf("app-%d", i%40),
			PID:      int32(1000 + i%40),
			SrcIP:    "192.168.1.5",
			SrcPort:  uint16(1024 + i%60000),
			// A realistic spread of destinations rather than one hot row.
			DstIP:     fmt.Sprintf("93.184.%d.%d", (i/256)%256, i%256),
			DstPort:   443,
			Proto:     types.ProtoTCP,
			Direction: types.DirOut,
			Active:    true,
		}
	}
	return flows
}

// BenchmarkWriteFlows measures sustained ingest in the shape the pipeline
// actually uses: batches inside one transaction, on the flush interval.
func BenchmarkWriteFlows(b *testing.B) {
	for _, batch := range []int{1, 50, 250, 1000} {
		b.Run(fmt.Sprintf("batch-%d", batch), func(b *testing.B) {
			s, err := Open(filepath.Join(b.TempDir(), "bench.db"))
			if err != nil {
				b.Fatalf("open: %v", err)
			}
			defer s.Close()

			ctx := context.Background()
			flows := benchFlows(b.N, time.Now())

			b.ResetTimer()
			for i := 0; i < len(flows); i += batch {
				end := min(i+batch, len(flows))
				if err := s.WriteFlows(ctx, flows[i:end]); err != nil {
					b.Fatalf("write: %v", err)
				}
			}
			b.StopTimer()

			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "flows/s")
		})
	}
}

// BenchmarkEgressQuery measures the Watchtower's own query against a database
// holding a realistic amount of history, since that runs every few seconds
// while someone watches the map.
func BenchmarkEgressQuery(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	const seeded = 200_000
	now := time.Now()

	flows := benchFlows(seeded, now.Add(-24*time.Hour))
	for i := 0; i < len(flows); i += 1000 {
		end := min(i+1000, len(flows))
		if err := s.WriteFlows(ctx, flows[i:end]); err != nil {
			b.Fatalf("seed: %v", err)
		}
	}
	// Endpoints must exist for the join to return anything.
	seen := make(map[string]EndpointSighting, 4096)
	for _, f := range flows {
		seen[f.DstIP] = Sighting(false, f.TSLast)
		if len(seen) >= 4096 {
			s.TouchEndpoints(ctx, seen)
			seen = make(map[string]EndpointSighting, 4096)
		}
	}
	s.TouchEndpoints(ctx, seen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Egress(ctx, Filter{
			Since:     now.Add(-24 * time.Hour),
			Direction: types.DirOut,
			Limit:     600,
		}); err != nil {
			b.Fatalf("query: %v", err)
		}
	}
}

// TestStorageFootprint measures bytes actually consumed per flow, which is the
// number the retention defaults depend on. It is a test rather than a benchmark
// so that it runs in CI and fails if the footprint regresses badly.
func TestStorageFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 100k rows")
	}

	path := filepath.Join(t.TempDir(), "footprint.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	const n = 100_000
	now := time.Now()

	flows := benchFlows(n, now)
	start := time.Now()
	for i := 0; i < len(flows); i += 1000 {
		end := min(i+1000, len(flows))
		if err := s.WriteFlows(ctx, flows[i:end]); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Checkpoint so the WAL's contents are counted in the main file.
	s.DB().Exec("PRAGMA wal_checkpoint(TRUNCATE)")

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	perFlow := float64(fi.Size()) / float64(n)
	rate := float64(n) / elapsed.Seconds()

	t.Logf("wrote %d flows in %v (%.0f flows/s)", n, elapsed.Round(time.Millisecond), rate)
	t.Logf("database %.1f MiB, %.0f bytes per flow", float64(fi.Size())/(1<<20), perFlow)

	// What the D3 defaults imply, at this footprint.
	cap := float64(DefaultRetention().MaxBytes)
	t.Logf("512 MiB cap holds ~%.1f million flows", cap/perFlow/1e6)
	for _, perDay := range []int{100_000, 500_000, 2_000_000} {
		days := cap / (perFlow * float64(perDay))
		t.Logf("  at %7d flows/day: cap reached in %5.1f days", perDay, days)
	}

	// A flow is a handful of small columns; anything approaching a kilobyte
	// each means an index or a schema change has gone wrong.
	if perFlow > 400 {
		t.Errorf("%.0f bytes per flow is larger than expected; check indexes", perFlow)
	}
	// The pipeline flushes every 2s, so anything below a few thousand per second
	// would not keep up with a busy network.
	//
	// **Measured everywhere, asserted only on a machine whose speed means
	// something.**
	//
	// Two things make this number unreliable as a gate. The race detector
	// instruments every memory access and costs roughly an order of magnitude.
	// And a shared CI runner is not a machine with a speed: this test writes
	// 100,000 rows through SQLite, so it is bounded by whatever disk the runner
	// happened to get, which varies by more than twenty times. Both were
	// predicted in this comment and the second one still shipped a red build:
	// 37,000 flows/s locally, 1,842 on a loaded runner, on identical code.
	//
	// So the rate is logged always and asserted only when neither applies. What
	// is left is a floor low enough that only a real collapse trips it, which
	// catches the thing worth catching: a change that makes writes
	// pathologically slow rather than merely slower.
	switch {
	case raceEnabled:
		t.Logf("race detector on: %.0f flows/s measured, not asserted", rate)
	case os.Getenv("CI") != "":
		t.Logf("shared runner: %.0f flows/s measured, not asserted", rate)
	case rate < 2000:
		t.Errorf("%.0f flows/s is too slow to keep up with ingest", rate)
	}

	// A floor that holds everywhere, including CI. Below this the pipeline
	// could not drain its 2s flush on any hardware, which is a defect rather
	// than a slow afternoon.
	if rate < 200 {
		t.Errorf("%.0f flows/s indicates a write path collapse, not a slow machine", rate)
	}
}
