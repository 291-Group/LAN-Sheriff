package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedContact gives a device a history of organizations, then a new one inside
// the window.
func seedContact(t *testing.T, s *Store, mac, ip string, historyOrgs int, newOrg string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-30 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: %v", err)
	}

	var flows []types.Flow
	port := uint16(1000)
	// The history: organizations first reached a month ago.
	for i := 0; i < historyOrgs; i++ {
		dst := "203.0." + itoaTest(i/250) + "." + itoaTest(i%250+1)
		s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
                   VALUES (?, ?, 0, ?, ?)`,
			dst, "Org"+itoaTest(i), now.Add(-30*24*time.Hour).Unix(), now.Unix())
		port++
		flows = append(flows, types.Flow{
			DeviceID: id, SrcIP: ip, DstIP: dst, DstPort: port, Proto: "tcp",
			TSStart: now.Add(-30 * 24 * time.Hour), TSLast: now.Add(-30 * 24 * time.Hour),
			Direction: "out", Established: true,
		})
	}
	// And the new acquaintance, inside the window.
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
               VALUES ('198.51.100.7', ?, 0, ?, ?)`, newOrg, now.Add(-5*time.Minute).Unix(), now.Unix())
	flows = append(flows, types.Flow{
		DeviceID: id, SrcIP: ip, DstIP: "198.51.100.7", DstPort: 443, Proto: "tcp",
		TSStart: now.Add(-5 * time.Minute), TSLast: now.Add(-time.Minute),
		Direction: "out", Established: true,
	})
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}
	return id
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A quiet appliance meeting somebody new is worth reporting.
func TestFirstContactReportsAQuietDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id := seedContact(t, s, "AA:BB:CC:F0:00:01", "192.168.1.60", 3, "Unfamiliar Ltd", now)

	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if got[0].Detail["org"] != "Unfamiliar Ltd" {
		t.Errorf("Detail lost the organization: %v", got[0].Detail)
	}
	if got[0].Score < 0.8 {
		t.Errorf("Score = %.2f; a device with three acquaintances meeting a fourth should score high", got[0].Score)
	}
}

// The point of the rule. A browser meets new organizations constantly, and
// saying so hundreds of times a day would make the whole list worthless.
func TestFirstContactStaysQuietForAChattyDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// 600 organizations over 30 days is 20 a day, an ordinary web browser.
	seedContact(t, s, "AA:BB:CC:F0:00:02", "192.168.1.61", 600, "Yet Another CDN", now)

	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("reported %d findings for a device that meets somebody new every hour: %+v", len(got), got)
	}
}

// Everything is unusual to a database that started an hour ago.
func TestFirstContactSilentWithoutBaseline(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	seedContact(t, s, "AA:BB:CC:F0:00:03", "192.168.1.62", 2, "Somebody New", now)

	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("claimed %d findings with an hour of history", len(got))
	}
}

// An organization met long ago is not a first contact now.
func TestFirstContactIgnoresOldAcquaintances(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	seedContact(t, s, "AA:BB:CC:F0:00:04", "192.168.1.63", 3, "Known Ltd", now)

	// A window that ends before the new contact happened.
	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now.Add(-time.Hour), Window: 10 * time.Minute, Baseline: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("reported %d findings outside the window", len(got))
	}
}

// The whole engine, end to end: rules run, findings land, the subject ranks.
func TestEngineRunProducesWantedEntries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id := seedContact(t, s, "AA:BB:CC:F0:00:05", "192.168.1.64", 4, "Newcomer Inc", now)

	e := &suspicion.Engine{
		Rules: []suspicion.Rule{suspicion.FirstContact{}},
		Sink:  s,
		DB:    s,
	}
	if err := e.Run(ctx, now, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	w, err := s.Wanted(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 1 || w[0].Subject != id {
		t.Fatalf("Wanted = %+v, want one entry for %q", w, id)
	}
	if w[0].Score <= 0 || w[0].Score > 1 {
		t.Errorf("Score = %.2f, out of range", w[0].Score)
	}

	// A second pass must not double it.
	before := w[0].Score
	if err := e.Run(ctx, now, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	w, _ = s.Wanted(ctx, 10)
	if w[0].Score != before {
		t.Errorf("a second pass changed the score from %.3f to %.3f", before, w[0].Score)
	}
}

// productionBaseline is the baseline the running system actually passes.
//
// The engine computes it as time.Since(the moment monitoring began), and
// monitoring begins when the first flow is recorded, so it is exactly the age
// of the oldest row, never more. A test that passes an arbitrary large value
// instead is describing an install whose history predates its own first flow,
// which cannot happen, and it will not notice a rule that depends on the
// difference.
//
// It did not notice one. Every test in this file passed 30 days against data a
// few hours old, and first_contact converted the baseline back into a timestamp
// to gate on. In production that timestamp resolved to the install moment
// itself, so the gate could pass only on the install second and never
// afterwards. The rule produced nothing on a real network for three days.
func productionBaseline(t *testing.T, s *Store, now time.Time) time.Duration {
	t.Helper()
	var oldest int64
	if err := s.db.QueryRow(`SELECT MIN(ts_start) FROM flows`).Scan(&oldest); err != nil {
		t.Fatalf("no flows seeded: %v", err)
	}
	return now.Sub(time.Unix(oldest, 0))
}

// The rule must fire under the baseline the engine really passes.
func TestFirstContactFiresUnderARealisticBaseline(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// **Another device establishes when monitoring began.**
	//
	// This detail is the whole test. Without it, seedContact makes its device's
	// oldest flow the oldest flow in the database, so the gate passes by equality
	// and the test goes green against a broken rule. In a real install the install moment belongs to
	// whichever device was seen first, and every other device's history starts
	// strictly later, which is the case the rule could not handle.
	older, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:F0:00:08", IP: "192.168.1.68", SeenAt: now.Add(-60 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES ('198.51.100.68', 'Long Standing Co', 0, ?, ?)`,
		now.Add(-60*24*time.Hour).Unix(), now.Unix())
	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: older, SrcIP: "192.168.1.68", DstIP: "198.51.100.68", DstPort: 443,
		Proto: "tcp", TSStart: now.Add(-60 * 24 * time.Hour),
		TSLast: now.Add(-60 * 24 * time.Hour), Direction: "out", Established: true,
	}}); err != nil {
		t.Fatal(err)
	}

	// The device under test: a month of history, met somebody new today.
	id := seedContact(t, s, "AA:BB:CC:F0:00:09", "192.168.1.69", 3, "Unfamiliar Ltd", now)

	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour,
		Baseline: productionBaseline(t, s, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("the rule reported nothing under the baseline the engine actually passes")
	}
	if got[0].Subject != id {
		t.Errorf("subject = %q, want %q", got[0].Subject, id)
	}
}

// A device seen for the first time minutes ago has no history in which it had
// not met somebody, so everything it does would be a first contact.
func TestFirstContactIgnoresADeviceWithNoHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Everything about this device, including its very first flow, is recent.
	// seedContact always lays down a month of history, which is the opposite of
	// what is wanted here, so this device is seeded directly.
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:F0:00:0A", IP: "192.168.1.70", SeenAt: now.Add(-10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES ('198.51.100.77', 'Unfamiliar Ltd', 0, ?, ?)`,
		now.Add(-10*time.Minute).Unix(), now.Unix())
	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: id, SrcIP: "192.168.1.70", DstIP: "198.51.100.77", DstPort: 443,
		Proto: "tcp", TSStart: now.Add(-10 * time.Minute), TSLast: now.Add(-time.Minute),
		Direction: "out", Established: true,
	}}); err != nil {
		t.Fatal(err)
	}

	got, err := suspicion.FirstContact{}.Evaluate(ctx, suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour,
		Baseline: productionBaseline(t, s, now),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o.Detail["org"] == "Unfamiliar Ltd" {
			t.Errorf("reported a first contact for a device with no history: %+v", o.Detail)
		}
	}
}
