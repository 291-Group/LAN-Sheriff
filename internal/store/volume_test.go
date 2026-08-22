package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedHourly gives a device an hourly connection history. perHour is called with
// the hour index counting back from now, so a test can shape the rhythm.
func seedHourly(t *testing.T, s *Store, mac, ip string, now time.Time,
	hours int, perHour func(hoursAgo int) int) string {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: mac, IP: ip, SeenAt: now.Add(-30 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}

	var flows []types.Flow
	port := 1024
	for h := 1; h <= hours; h++ {
		// Placed mid-hour so the bucketing is unambiguous.
		base := now.Add(-time.Duration(h) * time.Hour).Truncate(time.Hour).Add(30 * time.Minute)
		for i := 0; i < perHour(h); i++ {
			port++
			if port > 65000 {
				port = 1024
			}
			flows = append(flows, types.Flow{
				DeviceID: id, SrcIP: ip, DstIP: "198.51.100.60",
				DstPort: uint16(port), Proto: "tcp",
				TSStart:   base.Add(time.Duration(i) * time.Millisecond),
				TSLast:    base.Add(time.Duration(i) * time.Millisecond),
				Direction: "out", Established: true,
			})
		}
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}
	return id
}

func runVolume(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.VolumeAnomaly{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: time.Hour, Baseline: 14 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A device doing far more than it ever does.
func TestVolumeAnomalyCatchesASpike(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id := seedHourly(t, s, "AA:BB:CC:C1:00:01", "192.168.1.140", now, 80, func(h int) int {
		if h == 1 {
			return 900 // the most recent finished hour
		}
		return 20 + h%5
	})

	got := runVolume(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if c, _ := got[0].Detail["connections"].(int); c != 900 {
		t.Errorf("connections = %v, want 900", got[0].Detail["connections"])
	}
}

// Ordinary variation must not be reported, or the rule fires every evening.
func TestVolumeAnomalyIgnoresNormalVariation(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	// A daily rhythm: quiet at night, busy by day, with the last hour ordinary.
	seedHourly(t, s, "AA:BB:CC:C1:00:02", "192.168.1.141", now, 80, func(h int) int {
		hourOfDay := (now.Add(-time.Duration(h) * time.Hour)).Hour()
		if hourOfDay >= 9 && hourOfDay <= 22 {
			return 250
		}
		return 30
	})

	if got := runVolume(t, s, now); len(got) != 0 {
		t.Errorf("reported an ordinary daily rhythm as an anomaly: %+v", got)
	}
}

// A device that normally makes two connections an hour making twenty is
// proportionally enormous and practically nothing.
func TestVolumeAnomalyIgnoresTinyAbsoluteNumbers(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedHourly(t, s, "AA:BB:CC:C1:00:03", "192.168.1.142", now, 80, func(h int) int {
		if h == 1 {
			return 20
		}
		return 2
	})

	if got := runVolume(t, s, now); len(got) != 0 {
		t.Errorf("reported twenty connections as an anomaly: %+v", got)
	}
}

// Without a few days of history the daily rhythm is indistinguishable from an
// anomaly.
func TestVolumeAnomalyWaitsForHistory(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedHourly(t, s, "AA:BB:CC:C1:00:04", "192.168.1.143", now, 80, func(h int) int {
		if h == 1 {
			return 900
		}
		return 20
	})

	got, err := suspicion.VolumeAnomaly{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: time.Hour, Baseline: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("drew conclusions with half a day of history: %+v", got)
	}
}

// The reason for median-based statistics: one enormous hour in the history must
// not raise the bar so far that nothing is ever reported again.
func TestVolumeAnomalySurvivesAnOutlierInHistory(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedHourly(t, s, "AA:BB:CC:C1:00:05", "192.168.1.144", now, 80, func(h int) int {
		switch h {
		case 1:
			return 800 // the hour under test
		case 40:
			return 5000 // a huge download last week
		}
		return 20
	})

	if got := runVolume(t, s, now); len(got) != 1 {
		t.Errorf("a single outlier in the history hid a real spike: got %d", len(got))
	}
}

// The finding must carry what a sentence needs.
func TestVolumeAnomalyExplainsItself(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	seedHourly(t, s, "AA:BB:CC:C1:00:06", "192.168.1.145", now, 80, func(h int) int {
		if h == 1 {
			return 900
		}
		return 20
	})

	got := runVolume(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations", len(got))
	}
	for _, k := range []string{"connections", "typical", "times"} {
		if _, ok := got[0].Detail[k]; !ok {
			t.Errorf("Detail missing %q: %v", k, got[0].Detail)
		}
	}
}
