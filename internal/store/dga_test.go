package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func seedLookups(t *testing.T, s *Store, mac, ip string, now time.Time,
	names []string, answered bool) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-7 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}
	answers := ""
	if answered {
		answers = `["93.184.216.34"]`
	}
	for i, n := range names {
		if _, err := s.db.Exec(
			`INSERT INTO dns_events (ts, device_id, qname, qtype, answers) VALUES (?, ?, ?, 'A', ?)`,
			now.Add(-time.Duration(i+1)*time.Minute).Unix(), id, n, answers); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func runDGA(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.DGADomain{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

var generated = []string{
	"kqxvbnzmrtplwd.com", "xj4k9mzq7bvt.net", "vhzkpqrmxwbn.org",
	"zxcvbnmqwerty.info", "a7f3k9x2m8p1q4.biz", "mnbvcxzlkjhg.com",
}

// A burst of failed lookups to generated names is the case this rule exists for.
func TestDGACatchesABurstOfFailedGuesses(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedLookups(t, s, "AA:BB:CC:E0:00:01", "192.168.1.100", now, generated, false)

	got := runDGA(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if n, _ := got[0].Detail["names"].(int); n != len(generated) {
		t.Errorf("names = %v, want %d", got[0].Detail["names"], len(generated))
	}
	if got[0].Score < 0.6 {
		t.Errorf("Score = %.2f, want a high score", got[0].Score)
	}
}

// A name that resolves is somebody's real service, however odd it looks.
func TestDGAIgnoresNamesThatResolve(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedLookups(t, s, "AA:BB:CC:E0:00:02", "192.168.1.101", now, generated, true)

	if got := runDGA(t, s, now); len(got) != 0 {
		t.Errorf("reported %d findings for names that all resolved: %+v", len(got), got)
	}
}

// One failed lookup of a strange name is a typo or a dead link.
func TestDGANeedsSeveralGuesses(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedLookups(t, s, "AA:BB:CC:E0:00:03", "192.168.1.102", now, generated[:2], false)

	if got := runDGA(t, s, now); len(got) != 0 {
		t.Errorf("called two failed lookups a pattern: %+v", got)
	}
}

// Ordinary failed lookups happen constantly, dead links, typos, retired
// services, and must not be mistaken for guessing.
func TestDGAIgnoresOrdinaryFailedLookups(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedLookups(t, s, "AA:BB:CC:E0:00:04", "192.168.1.103", now, []string{
		"old-blog.example.com", "retired-service.net", "my-holiday-photos.org",
		"stackoverflow.com", "some-dead-startup.io", "internal-tool.company.com",
	}, false)

	if got := runDGA(t, s, now); len(got) != 0 {
		t.Errorf("reported ordinary failed lookups as guessing: %+v", got)
	}
}

// The same name retried is one guess, not several.
func TestDGACountsDistinctNames(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	repeated := []string{}
	for i := 0; i < 12; i++ {
		repeated = append(repeated, "kqxvbnzmrtplwd.com")
	}
	seedLookups(t, s, "AA:BB:CC:E0:00:05", "192.168.1.104", now, repeated, false)

	if got := runDGA(t, s, now); len(got) != 0 {
		t.Errorf("twelve retries of one name counted as a burst: %+v", got)
	}
}

// The finding must carry what a sentence needs.
func TestDGAExplainsItself(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedLookups(t, s, "AA:BB:CC:E0:00:06", "192.168.1.105", now, generated, false)

	got := runDGA(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations", len(got))
	}
	for _, k := range []string{"names", "example"} {
		if _, ok := got[0].Detail[k]; !ok {
			t.Errorf("Detail is missing %q: %v", k, got[0].Detail)
		}
	}
}
