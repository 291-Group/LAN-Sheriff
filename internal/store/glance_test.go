package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func TestGlanceCountsWhatIsNew(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// One organization first seen inside the window, one well outside it.
	s.db.Exec(`INSERT INTO endpoints (ip, org, is_internal, first_seen, last_seen) VALUES
		('1.1.1.1', 'Recent Corp', 0, ?, ?),
		('2.2.2.2', 'Old Corp',    0, ?, ?)`,
		now.Add(-2*time.Hour).Unix(), now.Unix(),
		now.Add(-40*time.Hour).Unix(), now.Unix())

	// Likewise for devices.
	newDev, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:11:01", IP: "192.168.1.20", SeenAt: now.Add(-time.Hour),
	})
	oldDev, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:11:02", IP: "192.168.1.21", SeenAt: now.Add(-72 * time.Hour),
	})
	if newDev == "" || oldDev == "" {
		t.Fatal("seed devices failed")
	}

	g, err := s.Glance(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.NewOrgs != 1 {
		t.Errorf("NewOrgs = %d, want 1", g.NewOrgs)
	}
	if g.NewDevices != 1 {
		t.Errorf("NewDevices = %d, want 1", g.NewDevices)
	}
	if g.DevicesKnown != 2 {
		t.Errorf("DevicesKnown = %d, want 2", g.DevicesKnown)
	}
}

func TestGlanceFindsTheLoudestDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	quiet, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:22:01", IP: "192.168.1.30", Hostname: "quiet-pi", SeenAt: now,
	})
	loud, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:22:02", IP: "192.168.1.31", Hostname: "loud-laptop", SeenAt: now,
	})

	var flows []types.Flow
	for i := 0; i < 3; i++ {
		flows = append(flows, types.Flow{
			DeviceID: quiet, SrcIP: "192.168.1.30", DstIP: "1.1.1.1", DstPort: uint16(1000 + i),
			Proto: "tcp", TSStart: now, TSLast: now, Direction: "out",
		})
	}
	for i := 0; i < 11; i++ {
		flows = append(flows, types.Flow{
			DeviceID: loud, SrcIP: "192.168.1.31", DstIP: "1.1.1.1", DstPort: uint16(2000 + i),
			Proto: "tcp", TSStart: now, TSLast: now, Direction: "out",
		})
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}

	g, err := s.Glance(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.LoudestID != loud {
		t.Errorf("LoudestID = %q, want %q", g.LoudestID, loud)
	}
	if g.LoudestDevice != "loud-laptop" {
		t.Errorf("LoudestDevice = %q, want %q", g.LoudestDevice, "loud-laptop")
	}
	if g.LoudestConns != 11 {
		t.Errorf("LoudestConns = %d, want 11", g.LoudestConns)
	}
}

// A quiet hour derived from twenty minutes of history is noise dressed as
// insight. It must report "unknown" rather than a number nobody should act on.
func TestGlanceWithholdsQuietestHourUntilThereIsHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: "d", SrcIP: "192.168.1.40", DstIP: "1.1.1.1", DstPort: 443,
		Proto: "tcp", TSStart: now.Add(-20 * time.Minute), TSLast: now, Direction: "out",
	}}); err != nil {
		t.Fatal(err)
	}

	g, err := s.Glance(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.QuietestHour != -1 {
		t.Errorf("QuietestHour = %d, want -1 with less than a day of history", g.QuietestHour)
	}
}

func TestGlanceReportsQuietestHourOnceThereIsHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Two days of hourly traffic, with one hour deliberately sparse.
	quietHour := (now.Hour() + 5) % 24
	var flows []types.Flow
	port := 1
	for h := 0; h < 48; h++ {
		ts := now.Add(-time.Duration(h) * time.Hour)
		n := 6
		if ts.Hour() == quietHour {
			n = 1
		}
		for i := 0; i < n; i++ {
			port++
			flows = append(flows, types.Flow{
				DeviceID: "d", SrcIP: "192.168.1.50", DstIP: "1.1.1.1",
				DstPort: uint16(port), Proto: "tcp", TSStart: ts, TSLast: ts, Direction: "out",
			})
		}
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}

	g, err := s.Glance(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if g.QuietestHour != quietHour {
		t.Errorf("QuietestHour = %d, want %d", g.QuietestHour, quietHour)
	}
}

// An empty database must answer without erroring, and without claiming anything.
func TestGlanceOnEmptyDatabase(t *testing.T) {
	s := newTestStore(t)
	g, err := s.Glance(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if g.NewOrgs != 0 || g.NewDevices != 0 || g.LoudestDevice != "" || g.QuietestHour != -1 {
		t.Errorf("empty database produced claims: %+v", g)
	}
}
