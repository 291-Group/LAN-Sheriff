package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func seedPlain(t *testing.T, s *Store, mac, ip string, now time.Time,
	dst string, port uint16, internal bool) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-7 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}
	flag := 0
	if internal {
		flag = 1
	}
	s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
	           VALUES (?, 'Somewhere Ltd', ?, ?, ?)`, dst, flag, now.Unix(), now.Unix())
	s.WriteFlows(ctx, []types.Flow{{
		DeviceID: id, SrcIP: ip, DstIP: dst, DstPort: port, Proto: "tcp",
		TSStart: now.Add(-10 * time.Minute), TSLast: now.Add(-9 * time.Minute),
		Direction: "out", Established: true,
	}})
	return id
}

func runPlain(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.Plaintext{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Telnet across the internet has no legitimate modern use.
func TestPlaintextCatchesTelnet(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedPlain(t, s, "AA:BB:CC:A1:00:01", "192.168.1.120", now, "198.51.100.30", 23, false)

	got := runPlain(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id || got[0].Detail["protocol"] != "Telnet" {
		t.Errorf("observation = %+v", got[0])
	}
	if got[0].Score < 0.9 {
		t.Errorf("Score = %.2f; Telnet should score near the top", got[0].Score)
	}
}

// The decision this rule is built around. Plain HTTP is constant on any healthy
// network (certificate checks, redirects, captive portals) and flagging it
// would fire hundreds of times a day while telling the user nothing they can act
// on.
func TestPlaintextIgnoresOrdinaryHTTP(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedPlain(t, s, "AA:BB:CC:A1:00:02", "192.168.1.121", now, "198.51.100.31", 80, false)

	if got := runPlain(t, s, now); len(got) != 0 {
		t.Errorf("reported ordinary HTTP: %+v", got)
	}
}

// A database on the local segment speaking its own protocol is normal.
func TestPlaintextIgnoresLocalTraffic(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedPlain(t, s, "AA:BB:CC:A1:00:03", "192.168.1.122", now, "192.168.1.50", 3306, true)

	if got := runPlain(t, s, now); len(got) != 0 {
		t.Errorf("reported a database on the local network: %+v", got)
	}
}

// Encrypted equivalents are not findings.
func TestPlaintextIgnoresEncryptedPorts(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	for i, port := range []uint16{443, 993, 995, 22, 8443} {
		seedPlain(t, s, "AA:BB:CC:A1:01:0"+string(rune('0'+i)),
			"192.168.1.13"+string(rune('0'+i)), now,
			"198.51.100.4"+string(rune('0'+i)), port, false)
	}
	if got := runPlain(t, s, now); len(got) != 0 {
		t.Errorf("reported encrypted protocols: %+v", got)
	}
}

// Three FTP servers is one problem, not three.
func TestPlaintextGroupsByProtocol(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	id := seedPlain(t, s, "AA:BB:CC:A1:00:04", "192.168.1.125", now, "198.51.100.50", 21, false)
	for _, dst := range []string{"198.51.100.51", "198.51.100.52"} {
		s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, is_internal, first_seen, last_seen)
		           VALUES (?, 'Another Ltd', 0, ?, ?)`, dst, now.Unix(), now.Unix())
		s.WriteFlows(ctx, []types.Flow{{
			DeviceID: id, SrcIP: "192.168.1.125", DstIP: dst, DstPort: 21, Proto: "tcp",
			TSStart: now.Add(-8 * time.Minute), TSLast: now.Add(-7 * time.Minute),
			Direction: "out", Established: true,
		}})
	}

	got := runPlain(t, s, now)
	if len(got) != 1 {
		t.Errorf("three FTP servers produced %d findings, want 1", len(got))
	}
}
