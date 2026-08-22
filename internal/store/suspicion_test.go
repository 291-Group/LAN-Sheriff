package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
)

func obs(subject, dedup string, score float64, at time.Time) suspicion.Observation {
	return suspicion.Observation{
		Subject: subject, SubjectType: "device", Score: score,
		Dedup: dedup, At: at, Detail: map[string]any{"org": "Example Corp"},
	}
}

// A rule running every five minutes must not turn one event into a hundred
// findings.
func TestObservationsDeduplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	for i := 0; i < 5; i++ {
		if err := s.RecordObservations(ctx, "first_contact", 1.0,
			[]suspicion.Observation{obs("dev-1", "first_contact:dev-1:Example Corp", 0.5, now)}); err != nil {
			t.Fatal(err)
		}
	}

	f, err := s.Findings(ctx, FindingOpen, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 {
		t.Fatalf("five passes produced %d findings, want 1", len(f))
	}
}

// Behaviour that gets worse should climb; behaviour that merely persists should
// not accumulate into a false crescendo.
func TestScoreTakesTheWorstNotTheSum(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	key := "first_contact:dev-2:Acme"

	s.RecordObservations(ctx, "first_contact", 1.0, []suspicion.Observation{obs("dev-2", key, 0.4, now)})
	s.RecordObservations(ctx, "first_contact", 1.0, []suspicion.Observation{obs("dev-2", key, 0.8, now)})
	s.RecordObservations(ctx, "first_contact", 1.0, []suspicion.Observation{obs("dev-2", key, 0.3, now)})

	f, _ := s.Findings(ctx, FindingOpen, 10)
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Score < 0.79 || f[0].Score > 0.81 {
		t.Errorf("Score = %.2f, want the worst seen (0.8), not a sum", f[0].Score)
	}
}

// A rule's weight is what keeps a noisy rule from dominating the list.
func TestWeightScalesTheContribution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.RecordObservations(ctx, "noisy", 0.25, []suspicion.Observation{obs("dev-3", "noisy:dev-3", 1.0, now)})
	s.RecordObservations(ctx, "rare", 1.0, []suspicion.Observation{obs("dev-4", "rare:dev-4", 1.0, now)})

	f, _ := s.Findings(ctx, FindingOpen, 10)
	byDevice := map[string]float64{}
	for _, x := range f {
		byDevice[x.Subject] = x.Score
	}
	if byDevice["dev-3"] >= byDevice["dev-4"] {
		t.Errorf("a light rule outweighed a heavy one: %v", byDevice)
	}
	if byDevice["dev-3"] < 0.24 || byDevice["dev-3"] > 0.26 {
		t.Errorf("weighted score = %.2f, want ~0.25", byDevice["dev-3"])
	}
}

// Several weak signals about one subject is the case worth surfacing.
func TestWantedCombinesSignalsAndCaps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// One device with three modest findings, another with a single larger one.
	for i, rule := range []string{"a", "b", "c"} {
		s.RecordObservations(ctx, rule, 1.0, []suspicion.Observation{
			obs("many", rule+":many", 0.3, now.Add(time.Duration(i)*time.Second)),
		})
	}
	s.RecordObservations(ctx, "d", 1.0, []suspicion.Observation{obs("one", "d:one", 0.5, now)})

	w, err := s.Wanted(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) < 2 {
		t.Fatalf("got %d subjects, want 2", len(w))
	}
	if w[0].Subject != "many" {
		t.Errorf("ranked %q first; three signals should outrank one larger signal", w[0].Subject)
	}
	if w[0].Findings != 3 {
		t.Errorf("Findings = %d, want 3", w[0].Findings)
	}

	// And a subject cannot exceed the top of the scale however much accumulates.
	for i := 0; i < 12; i++ {
		s.RecordObservations(ctx, "e", 1.0, []suspicion.Observation{
			obs("loud", "e:loud:"+string(rune('a'+i)), 0.9, now),
		})
	}
	w, _ = s.Wanted(ctx, 10)
	if w[0].Score > 1.0 {
		t.Errorf("Score = %.2f, want capped at 1", w[0].Score)
	}
}

// A finding is a claim about current behaviour. One that stopped happening long
// ago is history.
func TestFindingsExpire(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	s.RecordObservations(ctx, "old", 1.0, []suspicion.Observation{
		obs("dev-5", "old:dev-5", 0.6, now.Add(-30*24*time.Hour)),
	})
	s.RecordObservations(ctx, "new", 1.0, []suspicion.Observation{obs("dev-6", "new:dev-6", 0.6, now)})

	n, err := s.ExpireFindings(ctx, now, FindingTTL)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expired %d findings, want 1", n)
	}
	open, _ := s.Findings(ctx, FindingOpen, 10)
	if len(open) != 1 || open[0].Subject != "dev-6" {
		t.Errorf("the wrong finding survived: %+v", open)
	}
}

// A dismissed finding stays dismissed even while the behaviour continues.
//
// This is deliberate, a finding somebody has dealt with must not reappear
// every five minutes, and it is pinned here because it is not obvious from the
// upsert, which updates last_seen, score and detail but says nothing about
// status.
//
// It is also a trap for migrations. Migrations 11 and 12 marked findings
// `cleared` to retire conclusions the rules would no longer draw, which meant
// that any finding whose dedup key the rule still emits was refreshed forever
// and never shown again. Derived data must be **deleted**, never handed a status
// that belongs to the user; migration 13 undoes that and says so.
func TestDismissedFindingIsNotReopenedByRecurrence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	obs := []suspicion.Observation{{
		Subject: "device-1", SubjectType: "device", Score: 0.5,
		At: time.Now(), Dedup: "plaintext:device-1:23", Detail: map[string]any{"port": 23},
	}}
	if err := s.RecordObservations(ctx, "plaintext", 1, obs); err != nil {
		t.Fatal(err)
	}

	open, err := s.Findings(ctx, FindingOpen, 10)
	if err != nil || len(open) != 1 {
		t.Fatalf("expected one open finding, got %d (err=%v)", len(open), err)
	}
	if err := s.SetFindingStatus(ctx, open[0].ID, FindingCleared); err != nil {
		t.Fatal(err)
	}

	// The behaviour continues, so the rule emits the same key again.
	if err := s.RecordObservations(ctx, "plaintext", 1, obs); err != nil {
		t.Fatal(err)
	}
	again, err := s.Findings(ctx, FindingOpen, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a dismissed finding came back on recurrence: %+v", again)
	}
}
