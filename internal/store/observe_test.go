package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func observe(t *testing.T, s *Store, o types.Sighting) string {
	t.Helper()
	id, err := s.ObserveDevice(context.Background(), o)
	if err != nil {
		t.Fatalf("ObserveDevice: %v", err)
	}
	return id
}

func deviceCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	return n
}

func getDevice(t *testing.T, s *Store, id string) types.Device {
	t.Helper()
	devs, err := s.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	for _, d := range devs {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("device %s not found", id)
	return types.Device{}
}

// The same hardware address is the same device, however many times it is seen
// and whatever address it is holding.
func TestObserveSameMACIsOneDevice(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	a := observe(t, s, types.Sighting{MAC: "DC:A6:32:00:00:0D", IP: "192.168.68.52", SeenAt: now})
	b := observe(t, s, types.Sighting{MAC: "dc-a6-32-00-00-0d", IP: "192.168.68.52", SeenAt: now.Add(time.Minute)})

	if a != b {
		t.Errorf("same MAC produced two devices: %s and %s", a, b)
	}
	if n := deviceCount(t, s); n != 1 {
		t.Errorf("device count = %d, want 1", n)
	}
}

// DHCP hands the same machine a different address. That must not create a second
// device, and both addresses must stay attributable.
func TestObserveSurvivesDHCPChange(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	a := observe(t, s, types.Sighting{MAC: "30:CD:A7:00:00:03", IP: "192.168.68.58", SeenAt: now})
	b := observe(t, s, types.Sighting{MAC: "30:CD:A7:00:00:03", IP: "192.168.68.77", SeenAt: now.Add(time.Hour)})

	if a != b {
		t.Fatalf("a DHCP address change produced a second device")
	}
	addrs, err := s.DeviceAddresses(context.Background(), a)
	if err != nil {
		t.Fatalf("DeviceAddresses: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("addresses = %d, want 2 (the old address must stay attributable)", len(addrs))
	}
	if addrs[0].IP != "192.168.68.77" {
		t.Errorf("most recent address = %s, want 192.168.68.77", addrs[0].IP)
	}
}

// This is the case the whole identity model exists for. The neighbour table sees
// a hardware address, mDNS sees a hostname, and until something reports both
// they are two records. When that arrives they must become one.
func TestObserveMergesWhenEvidenceConnectsTwoRecords(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-2 * time.Hour)

	fromARP := observe(t, s, types.Sighting{
		MAC: "98:01:A7:00:00:0A", IP: "192.168.68.54", Source: "neighbour", SeenAt: base,
	})
	fromMDNS := observe(t, s, types.Sighting{
		Hostname: "Living-Room-TV.local", Name: "Living Room TV",
		Services: []string{"_airplay._tcp"}, Source: "mdns", SeenAt: base.Add(time.Minute),
	})
	if fromARP == fromMDNS {
		t.Fatal("unrelated observations were merged before any evidence connected them")
	}
	if n := deviceCount(t, s); n != 2 {
		t.Fatalf("device count = %d, want 2", n)
	}

	// A single advert carrying both the address and the name is the evidence.
	merged := observe(t, s, types.Sighting{
		MAC: "98:01:A7:00:00:0A", Hostname: "living-room-tv", IP: "192.168.68.54",
		Source: "mdns", SeenAt: base.Add(time.Hour),
	})

	if n := deviceCount(t, s); n != 1 {
		t.Fatalf("device count after merge = %d, want 1", n)
	}
	if merged != fromARP {
		t.Errorf("survivor = %s, want the older record %s", merged, fromARP)
	}

	d := getDevice(t, s, merged)
	if d.Name != "Living Room TV" {
		t.Errorf("Name = %q, want %q, the merge lost what only the absorbed record had", d.Name, "Living Room TV")
	}
	if d.MAC != "980" && d.MAC == "" {
		t.Error("MAC lost in merge")
	}
	svcs, err := s.DeviceServices(context.Background(), merged)
	if err != nil {
		t.Fatalf("DeviceServices: %v", err)
	}
	if len(svcs) != 1 || svcs[0].Service != "_airplay._tcp" {
		t.Errorf("services = %v, want [_airplay._tcp] carried through the merge", svcs)
	}
}

// A merge must not reset when the device was first seen, or the Roster's "new
// device" signal becomes meaningless.
func TestMergeKeepsOldestFirstSeen(t *testing.T) {
	s := newTestStore(t)
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	recent := time.Now().Truncate(time.Second)

	first := observe(t, s, types.Sighting{MAC: "AA:BB:CC:DD:EE:01", SeenAt: old})
	observe(t, s, types.Sighting{Hostname: "office-printer", SeenAt: recent})
	merged := observe(t, s, types.Sighting{MAC: "AA:BB:CC:DD:EE:01", Hostname: "office-printer", SeenAt: recent})

	if merged != first {
		t.Fatalf("survivor = %s, want %s", merged, first)
	}
	d := getDevice(t, s, merged)
	if !d.FirstSeen.Equal(old) {
		t.Errorf("FirstSeen = %v, want %v", d.FirstSeen, old)
	}
	if d.LastSeen.Before(recent) {
		t.Errorf("LastSeen = %v, want at least %v", d.LastSeen, recent)
	}
}

// A phone that re-derives its randomized address must be recognised by hostname
// rather than counted as a new device every time.
func TestRandomizedMACRotationMergesByHostname(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-time.Hour)

	before := observe(t, s, types.Sighting{
		MAC: "F6:C0:74:00:00:0F", Hostname: "alex-iphone", IP: "192.168.68.50", SeenAt: base,
	})
	after := observe(t, s, types.Sighting{
		MAC: "7A:11:22:33:44:55", Hostname: "alex-iphone", IP: "192.168.68.61", SeenAt: base.Add(time.Hour),
	})

	if before != after {
		t.Errorf("a randomized MAC rotation created a new device (%s then %s)", before, after)
	}
	if n := deviceCount(t, s); n != 1 {
		t.Errorf("device count = %d, want 1", n)
	}
	d := getDevice(t, s, before)
	if !d.MACRandomized {
		t.Error("MACRandomized = false, want true so the UI can say the address rotates")
	}
}

// DHCP eventually gives a released address to a different machine. Two distinct
// hardware addresses must stay two devices even when they share an IP.
func TestAddressReuseDoesNotMergeDevices(t *testing.T) {
	s := newTestStore(t)
	base := time.Now().Add(-time.Hour)

	a := observe(t, s, types.Sighting{MAC: "AA:BB:CC:00:00:01", IP: "192.168.68.90", SeenAt: base})
	b := observe(t, s, types.Sighting{MAC: "AA:BB:CC:00:00:02", IP: "192.168.68.90", SeenAt: base.Add(time.Hour)})

	if a == b {
		t.Error("two machines that shared an address over time were merged into one")
	}
	if n := deviceCount(t, s); n != 2 {
		t.Errorf("device count = %d, want 2", n)
	}
}

// A sighting with nothing to identify it by must not create a row that can never
// be merged with anything.
func TestObservationWithoutIdentityCreatesNothing(t *testing.T) {
	s := newTestStore(t)

	id := observe(t, s, types.Sighting{IP: "192.168.68.200", SeenAt: time.Now()})
	if id != "" {
		t.Errorf("id = %q, want empty", id)
	}
	if n := deviceCount(t, s); n != 0 {
		t.Errorf("device count = %d, want 0", n)
	}
}

// Once a device is known, a bare address resolves to it, which is how a flow
// gets attributed without re-observing the hardware address.
func TestBareAddressResolvesToKnownDevice(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	known := observe(t, s, types.Sighting{MAC: "AA:BB:CC:00:00:09", IP: "192.168.68.52", SeenAt: now})
	again := observe(t, s, types.Sighting{IP: "192.168.68.52", SeenAt: now.Add(time.Minute)})

	if again != known {
		t.Errorf("bare address resolved to %q, want %q", again, known)
	}
}

// A hostname reported in three different spellings is one device, not three.
func TestHostnameNormalization(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	a := observe(t, s, types.Sighting{Hostname: "Living-Room-TV.local", SeenAt: now})
	b := observe(t, s, types.Sighting{Hostname: "living-room-tv", SeenAt: now})
	c := observe(t, s, types.Sighting{Hostname: "LIVING-ROOM-TV.local.", SeenAt: now})

	if a != b || b != c {
		t.Errorf("one hostname in three spellings produced %s, %s, %s", a, b, c)
	}
	if n := deviceCount(t, s); n != 1 {
		t.Errorf("device count = %d, want 1", n)
	}
}

// Flows and DNS events already attributed to an absorbed record must follow it
// into the survivor. If they do not, a merge silently orphans traffic: the rows
// stay in the database pointing at a device ID that no longer exists, and they
// disappear from every per-device view without anything reporting an error.
func TestMergeRepointsTrafficToSurvivor(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-2 * time.Hour)

	fromARP := observe(t, s, types.Sighting{MAC: "AA:BB:CC:11:22:33", IP: "192.168.68.70", SeenAt: base})
	fromMDNS := observe(t, s, types.Sighting{Hostname: "media-box", SeenAt: base.Add(time.Minute)})
	if fromARP == fromMDNS {
		t.Fatal("records merged before any evidence connected them")
	}

	// Traffic recorded against the record that is about to be absorbed.
	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: fromMDNS, Proto: "tcp",
		SrcIP: "192.168.68.70", SrcPort: 51000,
		DstIP: "93.184.216.34", DstPort: 443,
		TSStart: base, TSLast: base, Direction: "out",
	}}); err != nil {
		t.Fatalf("UpsertFlows: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO dns_events (ts, device_id, qname, qtype) VALUES (?, ?, ?, ?)`,
		base.Unix(), fromMDNS, "example.com", "A"); err != nil {
		t.Fatalf("insert dns event: %v", err)
	}

	survivor := observe(t, s, types.Sighting{
		MAC: "AA:BB:CC:11:22:33", Hostname: "media-box", SeenAt: base.Add(time.Hour),
	})
	if survivor != fromARP {
		t.Fatalf("survivor = %s, want %s", survivor, fromARP)
	}

	for _, tbl := range []string{"flows", "dns_events"} {
		var orphaned int
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM `+tbl+` WHERE device_id = ?`, fromMDNS).Scan(&orphaned); err != nil {
			t.Fatalf("count orphaned %s: %v", tbl, err)
		}
		if orphaned != 0 {
			t.Errorf("%s: %d rows still point at the absorbed device", tbl, orphaned)
		}

		var moved int
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM `+tbl+` WHERE device_id = ?`, survivor).Scan(&moved); err != nil {
			t.Fatalf("count moved %s: %v", tbl, err)
		}
		if moved != 1 {
			t.Errorf("%s: survivor has %d rows, want 1", tbl, moved)
		}
	}
}

// A name the user chose outranks anything discovery finds, and must survive a
// merge even when the absorbed record also carried one.
func TestMergePreservesUserLabel(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)

	labelled := observe(t, s, types.Sighting{MAC: "AA:BB:CC:44:55:66", SeenAt: base})
	if _, err := s.db.ExecContext(ctx,
		`UPDATE devices SET label = ? WHERE id = ?`, "Kids' iPad", labelled); err != nil {
		t.Fatalf("set label: %v", err)
	}
	observe(t, s, types.Sighting{Hostname: "ipad-air", Name: "iPad Air", SeenAt: base.Add(time.Minute)})

	merged := observe(t, s, types.Sighting{
		MAC: "AA:BB:CC:44:55:66", Hostname: "ipad-air", Name: "iPad Air", SeenAt: base.Add(time.Hour),
	})
	d := getDevice(t, s, merged)
	if d.Label != "Kids' iPad" {
		t.Errorf("Label = %q, want %q, discovery overwrote a name the user chose", d.Label, "Kids' iPad")
	}
	if d.Name != "iPad Air" {
		t.Errorf("Name = %q, want %q", d.Name, "iPad Air")
	}
}

// The convergence case as it actually happens on a network.
//
// This is deliberately built from what the real sources can each report, not from
// a convenient observation carrying everything at once. The neighbour table sees a
// hardware address and an IP. mDNS sees a hostname and an IP. Neither can see the
// other's field (a socket cannot read the sender's hardware address) so if these
// two do not converge on the address, every device on the network appears twice
// forever.
func TestNeighbourAndMDNSConvergeOnOneDevice(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	fromNeighbour := observe(t, s, types.Sighting{
		MAC: "98:01:A7:00:00:0A", IP: "192.168.68.54",
		Vendor: "Apple, Inc.", Source: "neighbour", SeenAt: now,
	})
	fromMDNS := observe(t, s, types.Sighting{
		IP: "192.168.68.54", Hostname: "Living-Room-TV.local", Name: "Living Room TV",
		Services: []string{"_airplay._tcp"}, Source: "mdns", SeenAt: now.Add(2 * time.Second),
	})

	if fromNeighbour != fromMDNS {
		t.Fatalf("the two sources produced separate devices (%s, %s); every device would appear twice",
			fromNeighbour, fromMDNS)
	}
	if n := deviceCount(t, s); n != 1 {
		t.Fatalf("device count = %d, want 1", n)
	}

	d := getDevice(t, s, fromNeighbour)
	if d.MAC == "" || d.Hostname == "" || d.Name == "" || d.Vendor == "" {
		t.Errorf("converged device is missing fields: mac=%q hostname=%q name=%q vendor=%q",
			d.MAC, d.Hostname, d.Name, d.Vendor)
	}
}

// The same convergence in the other order: mDNS names a device before the
// neighbour table has an entry for it. The hardware address must attach to the
// existing record rather than start a second one.
func TestMDNSBeforeNeighbourStillConverges(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	fromMDNS := observe(t, s, types.Sighting{
		IP: "192.168.68.52", Hostname: "raspberrypi", Source: "mdns", SeenAt: now,
	})
	fromNeighbour := observe(t, s, types.Sighting{
		MAC: "DC:A6:32:00:00:0D", IP: "192.168.68.52",
		Vendor: "Raspberry Pi Trading Ltd", Source: "neighbour", SeenAt: now.Add(2 * time.Second),
	})

	if fromMDNS != fromNeighbour {
		t.Fatalf("order changed the outcome: %s then %s", fromMDNS, fromNeighbour)
	}
	d := getDevice(t, s, fromMDNS)
	if d.MAC == "" {
		t.Error("the hardware address did not attach to the device mDNS had already named")
	}
	if d.Vendor != "Raspberry Pi Trading Ltd" {
		t.Errorf("Vendor = %q, want the vendor the neighbour sighting supplied", d.Vendor)
	}
}

// The safeguard on that convergence: an address whose lease has moved to a
// different machine must not adopt the previous holder's identity, even though
// the address matches exactly.
func TestAddressHandoverIsNotConvergence(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	first := observe(t, s, types.Sighting{
		MAC: "AA:BB:CC:00:00:01", IP: "192.168.68.90", Hostname: "old-laptop", SeenAt: now,
	})
	second := observe(t, s, types.Sighting{
		MAC: "AA:BB:CC:00:00:02", IP: "192.168.68.90", Hostname: "new-tablet",
		SeenAt: now.Add(72 * time.Hour),
	})

	if first == second {
		t.Fatal("a reassigned address merged two unrelated machines")
	}
	d := getDevice(t, s, second)
	if d.Hostname != "new-tablet" {
		t.Errorf("Hostname = %q, want %q", d.Hostname, "new-tablet")
	}
}

// Traffic captured before a device had a name must end up on that device.
//
// Patrol tags a flow from another machine `lan-<address>`, because a packet
// carries no identity beyond an address. Nothing used to complete that
// sentence: on a real network a printer had 2,168 captured flows under
// `lan-192.168.68.58` while its Roster entry had none, one machine living as
// two, empty Rap Sheet, and a stranger to every rule that groups by device.
func TestPlaceholderFlowsAreAdoptedWhenTheDeviceIsNamed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Patrol saw the traffic first, before discovery knew whose it was.
	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: "lan-192.168.1.90", SrcIP: "192.168.1.90", DstIP: "93.184.216.34",
		DstPort: 443, Proto: "tcp", TSStart: now.Add(-time.Hour), TSLast: now,
		Direction: "out", Established: true,
	}}); err != nil {
		t.Fatal(err)
	}

	// Then discovery named the device.
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:E0:00:01", IP: "192.168.1.90", SeenAt: now,
	})
	if err != nil || id == "" {
		t.Fatalf("observe: err=%v id=%q", err, id)
	}

	var orphaned, adopted int
	s.db.QueryRow(`SELECT COUNT(*) FROM flows WHERE device_id = 'lan-192.168.1.90'`).Scan(&orphaned)
	s.db.QueryRow(`SELECT COUNT(*) FROM flows WHERE device_id = ?`, id).Scan(&adopted)
	if orphaned != 0 {
		t.Errorf("%d flows are still filed under the placeholder", orphaned)
	}
	if adopted != 1 {
		t.Errorf("the device has %d flows, want 1", adopted)
	}
}

// Once the device is known, no second identity should be created at all.
func TestFlowsWrittenAfterDiscoveryUseTheRealDevice(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:E0:00:02", IP: "192.168.1.91", SeenAt: now,
	})
	if err != nil || id == "" {
		t.Fatalf("observe: err=%v id=%q", err, id)
	}

	// Patrol still tags with a placeholder; it cannot know the device id.
	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: "lan-192.168.1.91", SrcIP: "192.168.1.91", DstIP: "93.184.216.34",
		DstPort: 443, Proto: "tcp", TSStart: now.Add(-time.Minute), TSLast: now,
		Direction: "out", Established: true,
	}}); err != nil {
		t.Fatal(err)
	}

	var placeholders int
	s.db.QueryRow(`SELECT COUNT(*) FROM flows WHERE device_id LIKE 'lan-%'`).Scan(&placeholders)
	if placeholders != 0 {
		t.Errorf("%d flows were written under a placeholder for a known device", placeholders)
	}
}

// A device that is genuinely unknown keeps its placeholder: the point is to
// resolve them when possible, not to throw away attribution.
func TestUnknownDeviceKeepsItsPlaceholder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	if err := s.WriteFlows(ctx, []types.Flow{{
		DeviceID: "lan-192.168.1.92", SrcIP: "192.168.1.92", DstIP: "93.184.216.34",
		DstPort: 443, Proto: "tcp", TSStart: now.Add(-time.Minute), TSLast: now,
		Direction: "out", Established: true,
	}}); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM flows WHERE device_id = 'lan-192.168.1.92'`).Scan(&n)
	if n != 1 {
		t.Errorf("an unidentified device lost its placeholder attribution")
	}
}
