package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedRhythm gives a device a series of connections to one destination at the
// given spacing, with an optional jitter applied alternately either side.
func seedRhythm(t *testing.T, s *Store, mac, ip, dst, org string,
	now time.Time, spacing time.Duration, jitter time.Duration, hits int) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-14 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: %v", err)
	}
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES (?, ?, 0, ?, ?)`, dst, org, now.Add(-14*24*time.Hour).Unix(), now.Unix())

	var flows []types.Flow
	for i := 0; i < hits; i++ {
		offset := time.Duration(hits-i) * spacing
		if jitter > 0 && i%2 == 0 {
			offset += jitter
		}
		ts := now.Add(-offset)
		flows = append(flows, types.Flow{
			DeviceID: id, SrcIP: ip, DstIP: dst, DstPort: uint16(40000 + i),
			Proto: "tcp", TSStart: ts, TSLast: ts.Add(time.Second),
			Direction: "out", Established: true,
		})
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}
	return id
}

func runBeaconing(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.Beaconing{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 14 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A tight rhythm to one destination is the case this rule exists for.
func TestBeaconingCatchesARegularRhythm(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedRhythm(t, s, "AA:BB:CC:B0:00:01", "192.168.1.70",
		"198.51.100.20", "Unknown Hosting", now, 5*time.Minute, 0, 20)

	got := runBeaconing(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if iv, _ := got[0].Detail["interval_secs"].(int); iv != 300 {
		t.Errorf("interval = %v, want 300", got[0].Detail["interval_secs"])
	}
	if got[0].Score < 0.7 {
		t.Errorf("Score = %.2f; a perfect five-minute rhythm should score high", got[0].Score)
	}
}

// Human-driven traffic is irregular, and reporting it would drown the list.
func TestBeaconingIgnoresIrregularTraffic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:B0:00:02", IP: "192.168.1.71", SeenAt: now.Add(-14 * 24 * time.Hour),
	})
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES ('198.51.100.21', 'Busy Site', 0, ?, ?)`, now.Add(-time.Hour).Unix(), now.Unix())

	// Gaps all over the place, as browsing produces.
	gaps := []time.Duration{31, 8, 140, 12, 400, 3, 77, 210, 19, 95, 6, 260}
	var flows []types.Flow
	at := now.Add(-6 * time.Hour)
	for i, g := range gaps {
		at = at.Add(g * time.Second)
		flows = append(flows, types.Flow{
			DeviceID: id, SrcIP: "192.168.1.71", DstIP: "198.51.100.21",
			DstPort: uint16(41000 + i), Proto: "tcp", TSStart: at, TSLast: at,
			Direction: "out", Established: true,
		})
	}
	s.WriteFlows(ctx, flows)

	if got := runBeaconing(t, s, now); len(got) != 0 {
		t.Errorf("reported %d rhythms in irregular traffic: %+v", len(got), got)
	}
}

// A keepalive on an open session is regular by design and says nothing.
func TestBeaconingIgnoresKeepalives(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedRhythm(t, s, "AA:BB:CC:B0:00:03", "192.168.1.72",
		"198.51.100.22", "Chat Service", now, 5*time.Second, 0, 40)

	if got := runBeaconing(t, s, now); len(got) != 0 {
		t.Errorf("reported a five-second keepalive as a beacon: %+v", got)
	}
}

// Three connections at similar spacing is an accident, not a schedule.
func TestBeaconingNeedsEnoughRepetitions(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedRhythm(t, s, "AA:BB:CC:B0:00:04", "192.168.1.73",
		"198.51.100.23", "Somewhere", now, 10*time.Minute, 0, 4)

	if got := runBeaconing(t, s, now); len(got) != 0 {
		t.Errorf("called four connections a schedule: %+v", got)
	}
}

// The reason for median-based statistics: a real beacon misses occasionally, and
// one doubled gap must not clear an otherwise perfect rhythm.
func TestBeaconingSurvivesAMissedInterval(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:B0:00:05", IP: "192.168.1.74", SeenAt: now.Add(-14 * 24 * time.Hour),
	})
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES ('198.51.100.24', 'Quiet Host', 0, ?, ?)`, now.Add(-12*time.Hour).Unix(), now.Unix())

	var flows []types.Flow
	at := now.Add(-6 * time.Hour)
	for i := 0; i < 16; i++ {
		at = at.Add(4 * time.Minute)
		// One beat skipped in the middle, exactly as a real beacon does.
		if i == 8 {
			at = at.Add(4 * time.Minute)
		}
		flows = append(flows, types.Flow{
			DeviceID: id, SrcIP: "192.168.1.74", DstIP: "198.51.100.24",
			DstPort: uint16(42000 + i), Proto: "tcp", TSStart: at, TSLast: at,
			Direction: "out", Established: true,
		})
	}
	s.WriteFlows(ctx, flows)

	got := runBeaconing(t, s, now)
	if len(got) != 1 {
		t.Fatalf("a single missed beat hid the rhythm: got %d observations", len(got))
	}
	if iv, _ := got[0].Detail["interval_secs"].(int); iv != 240 {
		t.Errorf("interval = %v, want 240 despite the gap", got[0].Detail["interval_secs"])
	}
}

// Jitter is what a beacon uses to hide. Modest jitter must still be caught.
func TestBeaconingToleratesJitter(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	// Ten per cent jitter on a ten-minute interval.
	seedRhythm(t, s, "AA:BB:CC:B0:00:06", "192.168.1.75",
		"198.51.100.25", "Hosting Co", now, 10*time.Minute, 60*time.Second, 24)

	if got := runBeaconing(t, s, now); len(got) != 1 {
		t.Errorf("ten per cent jitter defeated the rule: %+v", got)
	}
}

// The finding must carry enough for the interface to write a checkable sentence.
func TestBeaconingExplainsItself(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedRhythm(t, s, "AA:BB:CC:B0:00:07", "192.168.1.76",
		"198.51.100.26", "Example Hosting", now, 7*time.Minute, 0, 30)

	got := runBeaconing(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations", len(got))
	}
	// "addresses" rather than "address": a finding covers a destination service,
	// which is frequently many addresses, and naming one of twenty-seven would be
	// arbitrary. The count is what tells the reader why it is a single row.
	for _, k := range []string{"org", "addresses", "interval_secs", "hits", "regularity"} {
		if _, ok := got[0].Detail[k]; !ok {
			t.Errorf("Detail is missing %q, so the sentence cannot be written: %v", k, got[0].Detail)
		}
	}
	if got[0].Detail["org"] != "Example Hosting" {
		t.Errorf("org = %v", got[0].Detail["org"])
	}
}

// A finding must never present a country as an organization.
//
// Observed on a real network: `beaconing … {"org":"Canada"}`, which renders as
// "Connected to Canada every 60 minutes". The beacon was real; the sentence was
// a false statement about who owns the endpoint. Three rules each chose a
// different fallback for an unenriched endpoint, and two of them reached for the
// country. An address is honest, it says "we do not know who owns this".
func TestNoFindingCallsACountryAnOrganization(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	// Seeded with an empty org, which is common: the country database resolves
	// far more addresses than the ASN one names.
	const addr = "203.0.113.200"
	id := seedRhythm(t, s, "AA:BB:CC:D0:00:09", "192.168.1.190", addr, "",
		now, 60*time.Second, 0, 30)
	if id == "" {
		t.Fatal("no device seeded")
	}
	// Located but unattributed: exactly the row that produced "org":"Canada".
	if _, err := s.db.Exec(
		`UPDATE endpoints SET org='', country='CA', country_name='Canada' WHERE ip=?`,
		addr); err != nil {
		t.Fatal(err)
	}

	got := runBeaconing(t, s, now)
	if len(got) == 0 {
		t.Fatal("a regular beacon was not reported at all")
	}
	for _, o := range got {
		org, _ := o.Detail["org"].(string)
		if org == "Canada" || org == "CA" {
			t.Errorf("reported the country %q as the organization; an address would be honest", org)
		}
		if org == "" {
			t.Error("reported no destination at all")
		}
	}
}

// One service is one finding, however many addresses it answers on.
//
// A rhythm is measured per address, but a service is not an address: Tailscale's
// relays, a CDN and anything behind anycast all answer on many. Keying the
// finding on the address produced one row per address, on a real network, 55
// beaconing findings that were really six services, 27 of them the same one.
// A Wanted List with 74 rows for a single device is a list nobody reads.
func TestBeaconingGroupsOneServiceAcrossManyAddresses(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	// One organisation answering on five addresses, each with its own steady
	// rhythm, exactly what a relay network looks like.
	const org = "Relay Network, Inc."
	var id string
	for i := 0; i < 5; i++ {
		got := seedRhythm(t, s, "AA:BB:CC:E1:00:01", "192.168.1.60",
			fmt.Sprintf("198.51.100.%d", 40+i), org,
			now, 90*time.Second, 0, 20)
		if got != "" {
			id = got
		}
	}
	if id == "" {
		t.Fatal("no device seeded")
	}

	got := runBeaconing(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d findings for one service on five addresses, want 1", len(got))
	}
	if n, _ := got[0].Detail["addresses"].(int); n != 5 {
		t.Errorf("addresses = %v, want 5, the count is what justifies one row", got[0].Detail["addresses"])
	}
	// Hits are summed across the service, not taken from one address.
	if h, _ := got[0].Detail["hits"].(int); h < 100 {
		t.Errorf("hits = %v, want the total across all five addresses", got[0].Detail["hits"])
	}
}

// Two different organisations must stay two findings: grouping is by service,
// not by device.
func TestBeaconingKeepsDifferentServicesApart(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	seedRhythm(t, s, "AA:BB:CC:E1:00:02", "192.168.1.61",
		"198.51.100.80", "First Org", now, 90*time.Second, 0, 20)
	seedRhythm(t, s, "AA:BB:CC:E1:00:02", "192.168.1.61",
		"198.51.100.81", "Second Org", now, 120*time.Second, 0, 20)

	got := runBeaconing(t, s, now)
	if len(got) != 2 {
		t.Fatalf("got %d findings for two distinct services, want 2", len(got))
	}
}
