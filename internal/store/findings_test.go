package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The whole household is "new" to an empty database. Raising a finding for each
// would fill the Wanted List with the user's own devices on day one, which is
// the fastest way to teach somebody that these alerts are worthless.
func TestNoFindingsDuringTheInitialCensus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	for i := 0; i < 6; i++ {
		if _, err := s.ObserveDevice(ctx, types.Sighting{
			MAC:    "AA:BB:CC:00:33:0" + string(rune('0'+i)),
			IP:     "192.168.1.6" + string(rune('0'+i)),
			Source: "neighbour", SeenAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}

	f, err := s.Findings(ctx, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Errorf("got %d findings during the census, want 0", len(f))
	}
}

// Once the census is over, an arrival is genuinely news.
func TestArrivalAfterBaselineRaisesAFinding(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start := time.Now()

	// The census.
	if _, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:44:01", IP: "192.168.1.70", Source: "neighbour", SeenAt: start,
	}); err != nil {
		t.Fatal(err)
	}

	// A device that turns up well after it.
	later := start.Add(baselineGrace + time.Hour)
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:44:02", IP: "192.168.1.71", Hostname: "guest-phone",
		Vendor: "Acme", Source: "neighbour", SeenAt: later,
	})
	if err != nil {
		t.Fatal(err)
	}

	f, err := s.Findings(ctx, FindingOpen, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Rule != RuleNewDevice || f[0].Subject != id {
		t.Errorf("finding = %+v, want rule %q for %q", f[0], RuleNewDevice, id)
	}
	if f[0].Detail["hostname"] != "guest-phone" || f[0].Detail["vendor"] != "Acme" {
		t.Errorf("detail lost the facts: %v", f[0].Detail)
	}
	if f[0].Label != "guest-phone" {
		t.Errorf("Label = %q, want the device's display name", f[0].Label)
	}
}

// A device seen again is not an arrival, however long it was away.
func TestReturningDeviceRaisesNothing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start := time.Now()

	s.ObserveDevice(ctx, types.Sighting{MAC: "AA:BB:CC:00:55:01", IP: "192.168.1.80", SeenAt: start})
	after := start.Add(baselineGrace + time.Hour)
	s.ObserveDevice(ctx, types.Sighting{MAC: "AA:BB:CC:00:55:02", IP: "192.168.1.81", SeenAt: after})

	before, _ := s.Findings(ctx, "", 50)

	// The first device reappears a week later.
	s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:55:01", IP: "192.168.1.80", SeenAt: after.Add(7 * 24 * time.Hour),
	})

	got, _ := s.Findings(ctx, "", 50)
	if len(got) != len(before) {
		t.Errorf("a returning device raised %d new findings, want 0", len(got)-len(before))
	}
}

// This machine is not an arrival on its own network.
func TestSelfNeverRaisesAnArrival(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start := time.Now()

	s.ObserveDevice(ctx, types.Sighting{MAC: "AA:BB:CC:00:66:01", IP: "192.168.1.90", SeenAt: start})
	later := start.Add(baselineGrace + time.Hour)
	s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:66:02", IP: "192.168.1.91", IsSelf: true, Source: "self", SeenAt: later,
	})

	f, _ := s.Findings(ctx, "", 50)
	for _, x := range f {
		if x.Detail["ip"] == "192.168.1.91" {
			t.Error("this machine was reported as a new device")
		}
	}
}

// An unidentified arrival is the more interesting one, and must sort above a
// device that named itself.
func TestAnonymousArrivalScoresHigher(t *testing.T) {
	named := newDeviceScore(types.Sighting{Vendor: "Apple, Inc.", Hostname: "kitchen-ipad"})
	anon := newDeviceScore(types.Sighting{})
	if anon <= named {
		t.Errorf("anonymous %.2f should score above named %.2f", anon, named)
	}
	if anon > 1 {
		t.Errorf("score %.2f exceeds 1", anon)
	}
}

func TestFindingStatusChanges(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start := time.Now()

	s.ObserveDevice(ctx, types.Sighting{MAC: "AA:BB:CC:00:77:01", IP: "192.168.1.95", SeenAt: start})
	s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:77:02", IP: "192.168.1.96", SeenAt: start.Add(baselineGrace + time.Hour),
	})

	open, _ := s.Findings(ctx, FindingOpen, 10)
	if len(open) != 1 {
		t.Fatalf("got %d open findings, want 1", len(open))
	}
	if err := s.SetFindingStatus(ctx, open[0].ID, FindingCleared); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Findings(ctx, FindingOpen, 10); len(again) != 0 {
		t.Errorf("finding still open after being cleared")
	}
	if err := s.SetFindingStatus(ctx, open[0].ID, "nonsense"); err == nil {
		t.Error("an unknown status was accepted")
	}
	if err := s.SetFindingStatus(ctx, 99999, FindingCleared); err == nil {
		t.Error("changing a finding that does not exist reported success")
	}
}

// The case the lazy version got wrong.
//
// An established install already knows every device, so no creation happens and
// nothing would set the baseline. The first genuine arrival months later would
// then set the baseline to that instant and be suppressed by its own grace
// period, the one arrival the feature exists for would be the one it missed.
func TestFirstArrivalOnAnEstablishedInstallIsReported(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/established.db"

	// A first session that discovers the network, then closes.
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 3; i++ {
		first.ObserveDevice(ctx, types.Sighting{
			MAC:    "AA:BB:CC:00:88:0" + string(rune('0'+i)),
			IP:     "192.168.1.10" + string(rune('0'+i)),
			SeenAt: start,
		})
	}
	if f, _ := first.Findings(ctx, "", 10); len(f) != 0 {
		t.Fatalf("census raised %d findings", len(f))
	}
	first.Close()

	// A later session on the same database. The baseline must already exist, so
	// an arrival well past the grace window is reported.
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	var stored string
	if err := second.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, baselineKey).Scan(&stored); err != nil {
		t.Fatalf("baseline was never recorded: %v", err)
	}

	arrival := start.Add(baselineGrace + 24*time.Hour)
	id, err := second.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:99:01", IP: "192.168.1.200", Source: "neighbour", SeenAt: arrival,
	})
	if err != nil {
		t.Fatal(err)
	}

	f, err := second.Findings(ctx, FindingOpen, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Subject != id {
		t.Fatalf("got %d findings, want 1 for the arrival %q", len(f), id)
	}
}
