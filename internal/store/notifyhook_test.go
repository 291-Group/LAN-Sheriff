package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// A finding must be announced once when it appears, and never again while it
// persists. Announcing on every refresh would mean a message every five minutes
// for as long as a behaviour continues, which is how a notification channel
// becomes a muted one.
func TestOnFindingFiresOnceForRuleFindings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	var announced []string
	s.OnFinding = func(rule, subject string, score float64) {
		announced = append(announced, rule+":"+subject)
	}

	obs := []suspicion.Observation{{
		Subject: "dev-x", SubjectType: "device", Score: 0.7,
		Dedup: "beaconing:dev-x:1.1.1.1", At: now,
		Detail: map[string]any{"org": "Example"},
	}}

	for i := 0; i < 4; i++ {
		if err := s.RecordObservations(ctx, "beaconing", 1.0, obs); err != nil {
			t.Fatal(err)
		}
	}

	if len(announced) != 1 {
		t.Fatalf("four passes announced %d times, want 1: %v", len(announced), announced)
	}
	if announced[0] != "beaconing:dev-x" {
		t.Errorf("announced %q", announced[0])
	}
}

// A device arriving is announced with a name a person would recognise.
func TestOnFindingFiresForNewDevices(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	start := time.Now()

	// Establish the baseline, then move past its grace window.
	s.ObserveDevice(ctx, types.Sighting{MAC: "AA:BB:CC:D1:00:01", IP: "192.168.1.150", SeenAt: start})

	var announced []string
	s.OnFinding = func(rule, subject string, score float64) {
		announced = append(announced, rule+":"+subject)
	}

	later := start.Add(baselineGrace + time.Hour)
	if _, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:D1:00:02", IP: "192.168.1.151", Hostname: "guest-laptop", SeenAt: later,
	}); err != nil {
		t.Fatal(err)
	}

	if len(announced) != 1 || announced[0] != "new_device:guest-laptop" {
		t.Fatalf("announced %v, want one new_device for guest-laptop", announced)
	}
}

// The subject is resolved to the device's display name, not its opaque id: a
// notification saying "a1b2c3d4" would be useless on a lock screen.
func TestAnnouncedSubjectIsReadable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	id, _ := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:D1:00:03", IP: "192.168.1.152", Hostname: "kitchen-tablet", SeenAt: now,
	})

	var subject string
	s.OnFinding = func(rule, subj string, score float64) { subject = subj }

	s.RecordObservations(ctx, "beaconing", 1.0, []suspicion.Observation{{
		Subject: id, SubjectType: "device", Score: 0.8, Dedup: "b:" + id, At: now,
	}})

	if subject != "kitchen-tablet" {
		t.Errorf("announced subject = %q, want the device's name", subject)
	}
}

// Nothing configured must not panic or cost anything.
func TestNoCallbackIsSafe(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.RecordObservations(ctx, "beaconing", 1.0, []suspicion.Observation{{
		Subject: "dev-y", SubjectType: "device", Score: 0.5, Dedup: "b:dev-y", At: time.Now(),
	}}); err != nil {
		t.Fatal(err)
	}
}
