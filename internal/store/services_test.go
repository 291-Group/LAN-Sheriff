package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func TestObservedServicesFromPorts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	pi, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "DC:A6:32:00:00:01", IP: "192.168.1.52", Hostname: "pi", SeenAt: now,
	})
	if err != nil || pi == "" {
		t.Fatal("seed device")
	}

	if err := s.WriteFlows(ctx, []types.Flow{
		// Connections to the Pi: these reveal what it is listening on.
		{DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52", DstPort: 22, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true},
		{DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52", DstPort: 80, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true},
		// An ephemeral port is where a connection came from, not a service.
		{DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52", DstPort: 51234, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true},
		// A port with no useful convention must not invent a service.
		{DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52", DstPort: 7777, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true},
		// An external destination is not a device on this network.
		{DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "93.184.216.34", DstPort: 443, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.RefreshObservedServices(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	svcs, err := s.DeviceServices(ctx, pi)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range svcs {
		got[v.Service] = v.Source
	}

	if got["SSH"] != "observed" || got["HTTP"] != "observed" {
		t.Errorf("services = %v, want SSH and HTTP observed", got)
	}
	if len(got) != 2 {
		t.Errorf("services = %v, want exactly SSH and HTTP, an ephemeral or unconventional port must not become one", got)
	}
}

// mDNS and SSDP already record services; the observed ones must not displace
// them, and both must be distinguishable by source.
func TestObservedServicesCoexistWithAdvertised(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "30:CD:A7:00:00:01", IP: "192.168.1.58", Hostname: "printer",
		Services: []string{"_ipp._tcp"}, Source: "mdns", SeenAt: now,
	})

	s.WriteFlows(ctx, []types.Flow{{
		DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.58",
		DstPort: 631, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true,
	}})
	if _, err := s.RefreshObservedServices(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	svcs, _ := s.DeviceServices(ctx, id)
	bySource := map[string]string{}
	for _, v := range svcs {
		bySource[v.Service] = v.Source
	}
	if bySource["_ipp._tcp"] != "mdns" {
		t.Errorf("the advertised service lost its source: %v", bySource)
	}
	if bySource["IPP"] != "observed" {
		t.Errorf("the observed service was not recorded: %v", bySource)
	}
}

// A port number is evidence, not proof, and the table must not guess.
func TestPortsWithoutConventionAreNotNamed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:11:00:01", IP: "192.168.1.99", SeenAt: now,
	})
	var flows []types.Flow
	for _, p := range []uint16{1234, 4711, 29999, 65000} {
		flows = append(flows, types.Flow{
			DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.99",
			DstPort: p, Proto: "tcp", TSStart: now, TSLast: now, Direction: "out", Established: true,
		})
	}
	s.WriteFlows(ctx, flows)
	s.RefreshObservedServices(ctx, now.Add(-time.Hour))

	if svcs, _ := s.DeviceServices(ctx, id); len(svcs) != 0 {
		t.Errorf("invented %d services from ports with no convention: %v", len(svcs), svcs)
	}
}

// The regression this whole column exists for.
//
// The on-demand port check knocks on 35 ports. Every knock is a real outbound
// connection and the socket sampler sees all of them, established or not. Before
// connections carried that distinction, checking a device taught the Roster that
// the device offered every port we had tried, so using the feature fabricated
// evidence about the thing it was meant to describe.
func TestRefusedConnectionsAreNotServices(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "DC:A6:32:00:00:09", IP: "192.168.1.52", Hostname: "pi", SeenAt: now,
	})

	var flows []types.Flow
	// One port that answered.
	flows = append(flows, types.Flow{
		DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52",
		DstPort: 22, Proto: "tcp", TSStart: now, TSLast: now,
		Direction: "out", Established: true,
	})
	// And the knocks that did not, exactly as a port check produces them.
	for _, p := range []uint16{143, 443, 554, 993, 995, 3306, 3389, 5000} {
		flows = append(flows, types.Flow{
			DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52",
			DstPort: p, Proto: "tcp", TSStart: now, TSLast: now,
			Direction: "out", Established: false,
		})
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}

	if _, err := s.RefreshObservedServices(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	svcs, _ := s.DeviceServices(ctx, id)
	if len(svcs) != 1 || svcs[0].Service != "SSH" {
		names := []string{}
		for _, v := range svcs {
			names = append(names, v.Service)
		}
		t.Errorf("services = %v, want only SSH, the refused knocks became services", names)
	}
}

// A connection that came up and has since closed still proves something was
// listening, so the flag must not be lost when the flow is updated.
func TestEstablishedSurvivesFlowUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	f := types.Flow{
		DeviceID: "self", SrcIP: "192.168.1.10", DstIP: "192.168.1.52",
		DstPort: 22, Proto: "tcp", TSStart: now, TSLast: now,
		Direction: "out", Established: true, Active: true,
	}
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatal(err)
	}
	// The same flow later, now closed and reported without the flag.
	f.TSLast = now.Add(time.Minute)
	f.Active = false
	f.Established = false
	if err := s.WriteFlows(ctx, []types.Flow{f}); err != nil {
		t.Fatal(err)
	}

	var established int
	if err := s.db.QueryRow(
		`SELECT established FROM flows WHERE dst_port = 22`).Scan(&established); err != nil {
		t.Fatal(err)
	}
	if established != 1 {
		t.Error("a closed connection forgot that it had once been established")
	}
}
