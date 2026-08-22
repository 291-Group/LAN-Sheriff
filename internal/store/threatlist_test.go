package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedFlagged records lookups carrying a blocklist label, which is how the
// pipeline stores them: the label is applied when the lookup is observed, not
// when the rule runs.
func seedFlagged(t *testing.T, s *Store, mac, ip string, now time.Time,
	qname, category string, count int, answered bool) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}
	answers := ""
	if answered {
		answers = `["93.184.216.34"]`
	}
	for i := 0; i < count; i++ {
		if _, err := s.db.Exec(
			`INSERT INTO dns_events (ts, device_id, qname, qtype, answers, flagged)
			 VALUES (?, ?, ?, 'A', ?, ?)`,
			now.Add(-time.Duration(i+1)*time.Minute).Unix(), id, qname, answers, category); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// runThreatList evaluates with a deliberately tiny baseline. This rule must not
// care: a known-bad host is known-bad on a database that started ten minutes
// ago, which is what makes it the one rule that works on a fresh install.
func runThreatList(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.ThreatList{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The case the rule exists for, with no history to reason from.
func TestThreatListFiresWithoutABaseline(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedFlagged(t, s, "AA:BB:CC:F0:00:01", "192.168.1.110", now,
		"evil-c2.example.net", "malware", 3, true)

	got := runThreatList(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if got[0].Score < 0.8 {
		t.Errorf("Score = %.2f, want a high score for a list match", got[0].Score)
	}
}

// The decision that keeps the Wanted List readable. A browser touches dozens of
// tracker domains an hour; reporting them would bury the one that matters.
func TestThreatListIgnoresAdsAndTrackers(t *testing.T) {
	for _, category := range []string{"ads", "tracker", "telemetry"} {
		t.Run(category, func(t *testing.T) {
			s := newTestStore(t)
			now := time.Now()
			seedFlagged(t, s, "AA:BB:CC:F0:00:02", "192.168.1.111", now,
				"analytics.example.com", category, 40, true)

			if got := runThreatList(t, s, now); len(got) != 0 {
				t.Errorf("reported %d findings for category %q: %+v", len(got), category, got)
			}
		})
	}
}

// An unlabelled lookup is the overwhelmingly common case and must be silent.
func TestThreatListIgnoresUnlabelledLookups(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedFlagged(t, s, "AA:BB:CC:F0:00:03", "192.168.1.112", now,
		"www.wikipedia.org", "", 20, true)

	if got := runThreatList(t, s, now); len(got) != 0 {
		t.Errorf("reported unlabelled lookups: %+v", got)
	}
}

// A name that did not resolve still means the device tried, and the finding must
// say which happened rather than implying contact that never occurred.
func TestThreatListDistinguishesReachedFromTried(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedFlagged(t, s, "AA:BB:CC:F0:00:04", "192.168.1.113", now,
		"sinkholed-c2.example.net", "malware", 2, false)

	got := runThreatList(t, s, now)
	if len(got) != 1 {
		t.Fatalf("a failed lookup to a known-bad name was dropped: %+v", got)
	}
	if resolved, _ := got[0].Detail["resolved"].(bool); resolved {
		t.Error("resolved = true for lookups that returned no answer")
	}

	s2 := newTestStore(t)
	seedFlagged(t, s2, "AA:BB:CC:F0:00:05", "192.168.1.114", now,
		"live-c2.example.net", "malware", 2, true)
	got2 := runThreatList(t, s2, now)
	if len(got2) != 1 {
		t.Fatalf("got %d observations", len(got2))
	}
	if resolved, _ := got2[0].Detail["resolved"].(bool); !resolved {
		t.Error("resolved = false for lookups that returned an answer")
	}
	if got2[0].Score <= got[0].Score {
		t.Errorf("a name that resolves (%.2f) should outscore one that does not (%.2f)",
			got2[0].Score, got[0].Score)
	}
}

// Two different bad hosts are two things to go and look at, not one.
func TestThreatListSeparatesDomains(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedFlagged(t, s, "AA:BB:CC:F0:00:06", "192.168.1.115", now,
		"first-c2.example.net", "malware", 2, true)
	if _, err := s.db.Exec(
		`INSERT INTO dns_events (ts, device_id, qname, qtype, answers, flagged)
		 VALUES (?, ?, 'second-c2.example.net', 'A', '["1.2.3.4"]', 'malware')`,
		now.Add(-time.Minute).Unix(), id); err != nil {
		t.Fatal(err)
	}

	got := runThreatList(t, s, now)
	if len(got) != 2 {
		t.Fatalf("got %d observations, want 2: %+v", len(got), got)
	}
	if got[0].Dedup == got[1].Dedup {
		t.Errorf("two domains share dedup key %q", got[0].Dedup)
	}
}

// The same host looked up repeatedly is one finding, refreshed.
func TestThreatListDedupsRepeatedLookups(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedFlagged(t, s, "AA:BB:CC:F0:00:07", "192.168.1.116", now,
		"chatty-c2.example.net", "malware", 30, true)

	got := runThreatList(t, s, now)
	if len(got) != 1 {
		t.Fatalf("30 lookups of one name became %d findings: %+v", len(got), got)
	}
	if hits, _ := got[0].Detail["hits"].(int); hits != 30 {
		t.Errorf("hits = %v, want 30", got[0].Detail["hits"])
	}
}

// Old matches fall outside the window like any other observation.
func TestThreatListForgetsOldMatches(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedFlagged(t, s, "AA:BB:CC:F0:00:08", "192.168.1.117",
		now.Add(-30*24*time.Hour), "ancient-c2.example.net", "malware", 5, true)

	if got := runThreatList(t, s, now); len(got) != 0 {
		t.Errorf("reported a match from a month ago: %+v", got)
	}
}

// The finding must carry what the sentence needs.
func TestThreatListExplainsItself(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedFlagged(t, s, "AA:BB:CC:F0:00:09", "192.168.1.118", now,
		"evil-c2.example.net", "malware", 4, true)

	got := runThreatList(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations", len(got))
	}
	for _, k := range []string{"domain", "hits", "resolved"} {
		if _, ok := got[0].Detail[k]; !ok {
			t.Errorf("Detail is missing %q: %v", k, got[0].Detail)
		}
	}
}
