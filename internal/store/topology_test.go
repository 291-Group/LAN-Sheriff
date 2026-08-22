package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedTopology lays down a small but realistic network: two devices, a router,
// and traffic to three organizations.
func seedTopology(t *testing.T, s *Store) (laptop, phone string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()

	laptop, _ = s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:00:01", IP: "192.168.1.10", Hostname: "laptop", SeenAt: now,
	})
	phone, _ = s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:00:02", IP: "192.168.1.11", Hostname: "phone", SeenAt: now,
	})

	// Endpoints with organizations, which is what external nodes collapse to.
	for _, e := range []struct{ ip, org, country string }{
		{"93.184.216.34", "Example Corp", "US"},
		{"93.184.216.35", "Example Corp", "US"}, // same org, must merge
		{"1.1.1.1", "Cloudflare", "US"},
		{"8.8.8.8", "Google", "US"},
	} {
		if _, err := s.db.Exec(`
INSERT INTO endpoints (ip, org, country, is_internal, first_seen, last_seen)
VALUES (?, ?, ?, 0, ?, ?)`, e.ip, e.org, e.country, now.Add(-time.Hour).Unix(), now.Unix()); err != nil {
			t.Fatalf("seed endpoint: %v", err)
		}
	}

	flows := []types.Flow{
		{DeviceID: laptop, SrcIP: "192.168.1.10", DstIP: "93.184.216.34", DstPort: 443, Proto: "tcp", BytesOut: 100, TSStart: now, TSLast: now, Direction: "out"},
		{DeviceID: laptop, SrcIP: "192.168.1.10", DstIP: "93.184.216.35", DstPort: 443, Proto: "tcp", BytesOut: 200, TSStart: now, TSLast: now, Direction: "out"},
		{DeviceID: laptop, SrcIP: "192.168.1.10", DstIP: "1.1.1.1", DstPort: 443, Proto: "tcp", BytesOut: 50, TSStart: now, TSLast: now, Direction: "out"},
		{DeviceID: phone, SrcIP: "192.168.1.11", DstIP: "8.8.8.8", DstPort: 443, Proto: "tcp", BytesOut: 10, TSStart: now, TSLast: now, Direction: "out"},
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatalf("seed flows: %v", err)
	}
	return laptop, phone
}

// Many addresses belonging to one organization must be one node. Drawing a node
// per address is what makes a topology graph unreadable.
func TestTopologyCollapsesAddressesToOrganizations(t *testing.T) {
	s := newTestStore(t)
	seedTopology(t, s)

	topo, err := s.Topology(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}

	orgs := map[string]TopoNode{}
	for _, n := range topo.Nodes {
		if n.Kind == "org" {
			orgs[n.Label] = n
		}
	}
	if len(orgs) != 3 {
		t.Fatalf("got %d organizations, want 3: %v", len(orgs), keysOf(orgs))
	}
	// Two addresses, one organization, both flows counted against it.
	if ex := orgs["Example Corp"]; ex.Conns != 2 || ex.Bytes != 300 {
		t.Errorf("Example Corp: conns=%d bytes=%d, want 2 and 300", ex.Conns, ex.Bytes)
	}
}

func TestTopologyEdgesConnectDevicesToOrganizations(t *testing.T) {
	s := newTestStore(t)
	laptop, phone := seedTopology(t, s)

	topo, err := s.Topology(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]TopoNode{}
	for _, n := range topo.Nodes {
		byID[n.ID] = n
	}
	for _, e := range topo.Edges {
		if _, ok := byID[e.Source]; !ok {
			t.Errorf("edge source %q is not a node", e.Source)
		}
		if _, ok := byID[e.Target]; !ok {
			t.Errorf("edge target %q is not a node", e.Target)
		}
	}

	// The laptop reached two organizations, the phone one.
	count := map[string]int{}
	for _, e := range topo.Edges {
		count[e.Source]++
	}
	if count["dev:"+laptop] != 2 {
		t.Errorf("laptop has %d edges, want 2", count["dev:"+laptop])
	}
	if count["dev:"+phone] != 1 {
		t.Errorf("phone has %d edges, want 1", count["dev:"+phone])
	}
}

// A graph beyond a certain size stops being a diagram, so the quietest
// organizations are folded away, and the count is reported rather than hidden.
func TestTopologyTruncatesQuietestAndSaysSo(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	dev, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:00:03", IP: "192.168.1.12", Hostname: "busy", SeenAt: now,
	})

	// One noisy organization and many quiet ones.
	var flows []types.Flow
	for i := 0; i < maxOrgNodes+15; i++ {
		ip := "203.0." + itoa(i/256) + "." + itoa(i%256)
		s.db.Exec(`INSERT INTO endpoints (ip, org, is_internal, first_seen, last_seen) VALUES (?, ?, 0, ?, ?)`,
			ip, "Org"+itoa(i), now.Unix(), now.Unix())
		reps := 1
		if i == 0 {
			reps = 50
		}
		for r := 0; r < reps; r++ {
			flows = append(flows, types.Flow{
				DeviceID: dev, SrcIP: "192.168.1.12", DstIP: ip, DstPort: uint16(443 + r),
				Proto: "tcp", TSStart: now, TSLast: now, Direction: "out",
			})
		}
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}

	topo, err := s.Topology(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}

	orgs := 0
	var busiestKept bool
	for _, n := range topo.Nodes {
		if n.Kind == "org" {
			orgs++
			if n.Label == "Org0" {
				busiestKept = true
			}
		}
	}
	if orgs > maxOrgNodes {
		t.Errorf("kept %d organizations, want at most %d", orgs, maxOrgNodes)
	}
	if topo.Truncated != 15 {
		t.Errorf("Truncated = %d, want 15", topo.Truncated)
	}
	if !busiestKept {
		t.Error("truncation dropped the busiest organization")
	}
}

// Every edge must reference a node that exists, including after truncation,
// otherwise the force layout is handed a dangling reference.
func TestTopologyNeverEmitsDanglingEdges(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	dev, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:00:00:04", IP: "192.168.1.13", Hostname: "d", SeenAt: now,
	})

	var flows []types.Flow
	for i := 0; i < maxOrgNodes+5; i++ {
		ip := "198.51.100." + itoa(i%256)
		s.db.Exec(`INSERT INTO endpoints (ip, org, is_internal, first_seen, last_seen) VALUES (?, ?, 0, ?, ?)`,
			ip, "Q"+itoa(i), now.Unix(), now.Unix())
		flows = append(flows, types.Flow{
			DeviceID: dev, SrcIP: "192.168.1.13", DstIP: ip, DstPort: 443,
			Proto: "tcp", TSStart: now, TSLast: now, Direction: "out",
		})
	}
	s.WriteFlows(ctx, flows)

	topo, _ := s.Topology(ctx, Filter{})
	ids := map[string]bool{}
	for _, n := range topo.Nodes {
		ids[n.ID] = true
	}
	for _, e := range topo.Edges {
		if !ids[e.Source] || !ids[e.Target] {
			t.Fatalf("dangling edge %s -> %s", e.Source, e.Target)
		}
	}
}

// An empty database must produce empty arrays rather than nulls, so the client
// can iterate without guarding every access.
func TestTopologyEmptyIsArraysNotNull(t *testing.T) {
	s := newTestStore(t)
	topo, err := s.Topology(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if topo.Nodes == nil || topo.Edges == nil {
		t.Error("nil slices would serialize as null")
	}
}

func keysOf(m map[string]TopoNode) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func itoa(n int) string {
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
