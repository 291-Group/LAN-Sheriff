package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Patrol Mode writes far harder than Deputy Mode ever did, and it exposed a
// transaction that could not survive the pressure.
//
// `ObserveDevice` reads a device and then updates it, in one transaction. Under
// SQLite's default DEFERRED locking that transaction takes its read snapshot at
// the first SELECT and only requests the write lock afterwards, so a commit by
// any other connection in between makes the upgrade fail with
// SQLITE_BUSY_SNAPSHOT (517). `busy_timeout` does not cover that: it is not
// contention that clears if you wait, it is a stale snapshot.
//
// The observed symptom was device sightings being dropped:
//
//	could not record a device sighting source=neighbour
//	  err="database is locked (5) (SQLITE_BUSY)"
//	could not record a device sighting source=neighbour
//	  err="database is locked (517)"
//
// Silent data loss in the Roster, reported only as a warning. This test runs
// discovery and flow ingest against each other hard enough to reproduce it.
func TestConcurrentDiscoveryAndIngest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	const (
		devices     = 12
		rounds      = 25
		flowWriters = 3
	)

	var wg sync.WaitGroup
	errs := make(chan error, devices*rounds+flowWriters*rounds)

	// Discovery: many devices seen repeatedly, which is what a neighbour-table
	// sweep looks like on a busy network.
	for d := 0; d < devices; d++ {
		wg.Add(1)
		go func(d int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				_, err := s.ObserveDevice(ctx, types.Sighting{
					MAC:    fmt.Sprintf("AA:BB:CC:%02X:%02X:01", d, d),
					IP:     fmt.Sprintf("192.168.77.%d", d+10),
					Source: "neighbour",
					SeenAt: now,
				})
				if err != nil {
					errs <- fmt.Errorf("observe device %d round %d: %w", d, r, err)
					return
				}
			}
		}(d)
	}

	// Ingest: flows landing at the same time, which is what capture produces.
	for w := 0; w < flowWriters; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				ts := now.Add(-time.Duration(r) * time.Second).Unix()
				_, err := s.db.ExecContext(ctx, `
INSERT INTO flows (flow_hash, ts_start, ts_last, device_id, src_ip, src_port,
                   dst_ip, dst_port, proto, direction, established, active)
VALUES (?, ?, ?, NULL, ?, ?, '203.0.113.5', 443, 'tcp', 'out', 1, 0)`,
					int64(w*100000+r), ts, ts,
					fmt.Sprintf("192.168.77.%d", w+10), 40000+r)
				if err != nil {
					errs <- fmt.Errorf("flow writer %d round %d: %w", w, r, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errs)

	var failures []error
	for err := range errs {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		t.Errorf("%d writes were lost under concurrent load; first: %v",
			len(failures), failures[0])
	}

	// Every device must have survived. A dropped sighting is a device missing
	// from the Roster, which is the failure a user would actually notice.
	var got int
	// Stored with separators, as the sighting supplied them.
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE mac LIKE 'AA:BB:CC:%'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != devices {
		t.Errorf("recorded %d of %d devices", got, devices)
	}
}
