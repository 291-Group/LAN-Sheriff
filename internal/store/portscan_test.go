package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func seedScanner(t *testing.T, s *Store, mac, ip string, now time.Time) string {
	t.Helper()
	id, err := s.ObserveDevice(context.Background(), types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-7 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}
	return id
}

func runScan(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.PortScan{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// One host, many ports, mostly refused.
func TestPortScanCatchesVerticalSweep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedScanner(t, s, "AA:BB:CC:F1:00:01", "192.168.1.110", now)

	var flows []types.Flow
	for p := 1; p <= 40; p++ {
		flows = append(flows, types.Flow{
			DeviceID: id, Process: "nmap", SrcIP: "192.168.1.110", DstIP: "192.168.1.5",
			DstPort: uint16(p), Proto: "tcp", TSStart: now.Add(-5 * time.Minute),
			TSLast: now.Add(-5 * time.Minute), Direction: "internal", Established: p <= 2,
		})
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}

	got := runScan(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Detail["shape"] != "vertical" {
		t.Errorf("shape = %v", got[0].Detail["shape"])
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
}

// One port, many hosts, how a worm looks for somewhere to go.
func TestPortScanCatchesHorizontalSweep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedScanner(t, s, "AA:BB:CC:F1:00:02", "192.168.1.111", now)

	var flows []types.Flow
	for h := 1; h <= 40; h++ {
		flows = append(flows, types.Flow{
			DeviceID: id, Process: "worm", SrcIP: "192.168.1.111",
			DstIP: "192.168.1." + itoaTest(h), DstPort: 445, Proto: "tcp",
			TSStart: now.Add(-4 * time.Minute), TSLast: now.Add(-4 * time.Minute),
			Direction: "internal", Established: false,
		})
	}
	s.WriteFlows(ctx, flows)

	got := runScan(t, s, now)
	if len(got) != 1 || got[0].Detail["shape"] != "horizontal" {
		t.Fatalf("got %+v, want one horizontal finding", got)
	}
	if p, _ := got[0].Detail["port"].(int); p != 445 {
		t.Errorf("port = %v, want 445", got[0].Detail["port"])
	}
}

// The trap this rule was written around: LAN Sheriff's own port check probes 35
// ports on one host, which is exactly the vertical shape.
func TestPortScanIgnoresOurOwnPortCheck(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedScanner(t, s, "AA:BB:CC:F1:00:03", "192.168.1.112", now)

	var flows []types.Flow
	for p := 1; p <= 40; p++ {
		flows = append(flows, types.Flow{
			DeviceID: id, Process: "lan-sheriff", SrcIP: "192.168.1.112",
			DstIP: "192.168.1.52", DstPort: uint16(p), Proto: "tcp",
			TSStart: now.Add(-3 * time.Minute), TSLast: now.Add(-3 * time.Minute),
			Direction: "internal", Established: false,
		})
	}
	s.WriteFlows(ctx, flows)

	if got := runScan(t, s, now); len(got) != 0 {
		t.Errorf("the application reported its own port check as a scan: %+v", got)
	}
}

// Software that touches many ports and *connects* is working, not scanning.
// FileZilla and a stream deck both did this on the development network.
func TestPortScanIgnoresSoftwareThatConnects(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedScanner(t, s, "AA:BB:CC:F1:00:04", "192.168.1.113", now)

	var flows []types.Flow
	for p := 1; p <= 40; p++ {
		flows = append(flows, types.Flow{
			DeviceID: id, Process: "FileZilla", SrcIP: "192.168.1.113",
			DstIP: "192.168.1.60", DstPort: uint16(50000 + p), Proto: "tcp",
			TSStart: now.Add(-2 * time.Minute), TSLast: now.Add(-2 * time.Minute),
			Direction: "internal", Established: true,
		})
	}
	s.WriteFlows(ctx, flows)

	if got := runScan(t, s, now); len(got) != 0 {
		t.Errorf("reported software that connected successfully as a scan: %+v", got)
	}
}

// A handful of ports is ordinary. The threshold sits above what real software
// was observed doing.
func TestPortScanIgnoresAFewPorts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedScanner(t, s, "AA:BB:CC:F1:00:05", "192.168.1.114", now)

	var flows []types.Flow
	for p := 1; p <= 12; p++ {
		flows = append(flows, types.Flow{
			DeviceID: id, Process: "Elgato Stream Deck", SrcIP: "192.168.1.114",
			DstIP: "192.168.1.61", DstPort: uint16(8000 + p), Proto: "tcp",
			TSStart: now.Add(-time.Minute), TSLast: now.Add(-time.Minute),
			Direction: "internal", Established: false,
		})
	}
	s.WriteFlows(ctx, flows)

	if got := runScan(t, s, now); len(got) != 0 {
		t.Errorf("twelve ports reported as a scan: %+v", got)
	}
}
