package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Patrol Mode sees a packet from an address before anything has established
// which machine holds it, so it tags the flow with a placeholder (`lan-<ip>`)
// rather than a device identifier. The real identity arrives afterwards, from a
// MAC in the neighbour table or a name over mDNS, and lands in
// `device_addresses`.
//
// Every read path therefore has to resolve a flow's device *through the address
// table*, not from the column on the flow. The suspicion rules always did. The
// view filter and the busiest-device widget did not, and the consequence was
// user-visible and severe: the Roster listed a printer, capture held 167 flows
// from it, and asking to see that device's traffic returned an empty screen.
//
// This reproduces exactly that shape: a device known by MAC, and flows carrying
// only the placeholder.
func TestPatrolFlowsResolveToTheirDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	const ip = "192.168.68.58"
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "30:CD:A7:00:00:03", IP: ip, Name: "Samsung M2020",
		Source: "neighbour", SeenAt: now.Add(-time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}

	if _, err := s.db.Exec(`
INSERT INTO endpoints (ip, org, country, first_seen, last_seen, is_internal)
VALUES ('203.0.113.7', 'Example Org', 'US', ?, ?, 0)`,
		now.Add(-time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}

	// Flows as Patrol writes them: the placeholder, never the device id.
	const flows = 12
	for i := 0; i < flows; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute).Unix()
		if _, err := s.db.Exec(`
INSERT INTO flows (flow_hash, ts_start, ts_last, device_id, src_ip, src_port,
                   dst_ip, dst_port, proto, direction, established, active)
VALUES (?, ?, ?, ?, ?, ?, '203.0.113.7', 443, 'tcp', 'out', 1, 0)`,
			int64(770000+i), ts, ts, "lan-"+ip, ip, 40000+i); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("filtering by the device finds its traffic", func(t *testing.T) {
		got, err := s.Egress(ctx, Filter{
			Device: id, Since: now.Add(-2 * time.Hour), Until: now.Add(time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Fatal("no destinations for a device with captured flows, " +
				"the filter matched the placeholder instead of resolving it")
		}
	})

	t.Run("the busiest device is named, not a placeholder", func(t *testing.T) {
		g, err := s.Glance(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if g.LoudestID != id {
			t.Errorf("loudest device id = %q, want the resolved device %q", g.LoudestID, id)
		}
		if g.LoudestDevice == "lan-"+ip || g.LoudestDevice == "" {
			t.Errorf("loudest device shown as %q, a placeholder is not a name", g.LoudestDevice)
		}
		if g.LoudestConns < flows {
			t.Errorf("counted %d connections, want at least %d, traffic was split "+
				"between the placeholder and the real identity", g.LoudestConns, flows)
		}
	})
}
