package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// seedShape gives a network a history concentrated in a few countries, then a
// single connection somewhere it essentially never goes.
func seedShape(t *testing.T, s *Store, now time.Time, bulk int) (string, func(country, org, ip string, when time.Time)) {
	t.Helper()
	ctx := context.Background()
	id, err := s.ObserveDevice(ctx, types.Sighting{
		MAC: "AA:BB:CC:D0:00:11", IP: "192.168.1.80", SeenAt: now.Add(-30 * 24 * time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("seed device: err=%v id=%q", err, id)
	}

	add := func(country, org, ip string, when time.Time) {
		s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, country, country_name, is_internal, first_seen, last_seen)
		           VALUES (?, ?, ?, ?, 0, ?, ?)`,
			ip, org, country, country+"-land", when.Unix(), when.Unix())
		s.WriteFlows(ctx, []types.Flow{{
			DeviceID: id, SrcIP: "192.168.1.80", DstIP: ip, DstPort: 443,
			Proto: "tcp", TSStart: when, TSLast: when, Direction: "out", Established: true,
		}})
	}

	// The network's ordinary shape: a lot of traffic to two countries.
	var flows []types.Flow
	for i := 0; i < bulk; i++ {
		country := "CA"
		if i%3 == 0 {
			country = "US"
		}
		ip := "203.0." + itoaTest(i/250) + "." + itoaTest(i%250+1)
		s.db.Exec(`INSERT OR IGNORE INTO endpoints (ip, org, country, country_name, is_internal, first_seen, last_seen)
		           VALUES (?, 'Ordinary Co', ?, ?, 0, ?, ?)`,
			ip, country, country+"-land", now.Add(-20*24*time.Hour).Unix(), now.Unix())
		flows = append(flows, types.Flow{
			DeviceID: id, SrcIP: "192.168.1.80", DstIP: ip, DstPort: uint16(1024 + i%40000),
			Proto: "tcp", TSStart: now.Add(-20 * 24 * time.Hour), TSLast: now.Add(-20 * 24 * time.Hour),
			Direction: "out", Established: true,
		})
	}
	if err := s.WriteFlows(ctx, flows); err != nil {
		t.Fatal(err)
	}
	return id, add
}

func runRare(t *testing.T, s *Store, now time.Time) []suspicion.Observation {
	t.Helper()
	got, err := suspicion.RareDestination{}.Evaluate(context.Background(), suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Somewhere this network essentially never goes.
func TestRareDestinationNoticesTheUnusual(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	id, add := seedShape(t, s, now, 2000)

	add("KP", "Unfamiliar Hosting", "198.51.100.90", now.Add(-10*time.Minute))

	got := runRare(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1: %+v", len(got), got)
	}
	if got[0].Subject != id {
		t.Errorf("Subject = %q, want %q", got[0].Subject, id)
	}
	if got[0].Detail["country_code"] != "KP" {
		t.Errorf("Detail = %v", got[0].Detail)
	}
	// One in two thousand is half the rarity threshold, so the score is
	// moderate. On a real network with far more history the same single
	// connection is a far smaller share and scores much higher; the curve is
	// checked directly in TestRareScoreCurve.
	if got[0].Score < 0.6 {
		t.Errorf("Score = %.2f, want a meaningful score for one connection in two thousand", got[0].Score)
	}
}

// Where the network goes all the time is not remarkable.
func TestRareDestinationIgnoresTheOrdinary(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 2000)

	// More traffic to a country that already dominates the history.
	add("CA", "Ordinary Co", "198.51.100.91", now.Add(-10*time.Minute))

	if got := runRare(t, s, now); len(got) != 0 {
		t.Errorf("reported %d findings for an everyday destination: %+v", len(got), got)
	}
}

// With a small sample every destination looks rare, because everything does.
func TestRareDestinationWaitsForEnoughHistory(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 20)

	add("KP", "Unfamiliar Hosting", "198.51.100.92", now.Add(-10*time.Minute))

	if got := runRare(t, s, now); len(got) != 0 {
		t.Errorf("drew conclusions from twenty connections: %+v", got)
	}
}

// One country and one device is one finding, however many addresses are involved.
func TestRareDestinationGroupsByCountry(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	// Enough history that three connections are still rare: at 2,000 flows they
	// would be 0.15% and correctly above the threshold.
	_, add := seedShape(t, s, now, 6000)

	for i, ip := range []string{"198.51.100.93", "198.51.100.94", "198.51.100.95"} {
		add("KP", "Unfamiliar Hosting", ip, now.Add(-time.Duration(i+1)*time.Minute))
	}

	got := runRare(t, s, now)
	seen := map[string]bool{}
	for _, o := range got {
		if seen[o.Dedup] {
			t.Errorf("duplicate dedup key %q", o.Dedup)
		}
		seen[o.Dedup] = true
	}
	if len(seen) != 1 {
		t.Errorf("three addresses in one country produced %d distinct findings", len(seen))
	}
}

// The finding must carry what a sentence needs, and must never carry a verdict.
func TestRareDestinationExplainsItself(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 2000)
	add("KP", "Unfamiliar Hosting", "198.51.100.96", now.Add(-5*time.Minute))

	got := runRare(t, s, now)
	if len(got) != 1 {
		t.Fatalf("got %d observations", len(got))
	}
	for _, k := range []string{"country", "country_code", "org", "share_pct", "country_hits", "total_hits"} {
		if _, ok := got[0].Detail[k]; !ok {
			t.Errorf("Detail is missing %q: %v", k, got[0].Detail)
		}
	}
	if share, _ := got[0].Detail["share_pct"].(float64); share <= 0 || share > 0.1 {
		t.Errorf("share_pct = %v, want a small positive percentage", got[0].Detail["share_pct"])
	}
}

// The shape of the curve, independent of any fixture's size.
func TestRareScoreCurve(t *testing.T) {
	cases := []struct {
		share float64
		want  string
	}{
		{0.002, "zero"},   // twice the threshold: not rare
		{0.001, "zero"},   // exactly the threshold
		{0.0005, "mid"},   // half the threshold
		{0.00001, "high"}, // a hundredth of it
	}
	var last float64 = 2
	for _, c := range cases {
		got := suspicion.RareScoreForTest(c.share)
		switch c.want {
		case "zero":
			if got != 0 {
				t.Errorf("share %.5f scored %.2f, want 0", c.share, got)
			}
		case "mid":
			if got < 0.5 || got > 0.8 {
				t.Errorf("share %.5f scored %.2f, want a middling score", c.share, got)
			}
		case "high":
			if got < 0.85 {
				t.Errorf("share %.5f scored %.2f, want a high score", c.share, got)
			}
		}
		// The cases run from common to rare, so the score must never fall.
		if c.want != "zero" {
			if last != 2 && got < last {
				t.Errorf("share %.5f scored %.2f, lower than the more common case's %.2f",
					c.share, got, last)
			}
			last = got
		}
	}
}

// A content network answering from a nearby edge is not a rare destination.
//
// This is the false-positive class that dominated the rule on a real network:
// fifteen of seventeen findings were Akamai, Google, Amazon and friends being
// reached in a country this network rarely sees, which is what a content
// network does by design. The one finding worth reading, a single connection
// to a government host, was buried underneath them.
func TestRareDestinationIgnoresDistributedOperators(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 2000)

	// This network already reaches Globalcast in plenty of countries, which is
	// how it is known to be distributed. Nothing is shipped about who it is.
	for i, c := range []string{"US", "CA", "GB", "DE", "JP", "SG", "BR", "ZA"} {
		for n := 0; n < 6; n++ {
			ip := "198.51.100." + itoaTest(100+i*6+n)
			add(c, "Globalcast", ip, now.Add(-15*24*time.Hour))
		}
	}

	// Now it answers from a country this network barely touches.
	add("AU", "Globalcast", "198.51.100.201", now.Add(-10*time.Minute))

	for _, o := range runRare(t, s, now) {
		if o.Detail["org"] == "Globalcast" {
			t.Errorf("reported a distributed operator as a rare destination: %+v", o.Detail)
		}
	}
}

// The guard must not swallow the finding the rule exists for. An operator this
// network has only ever reached in one place is exactly as rare as the place.
//
// The numbers here are small on purpose, and writing this test is what made the
// reason clear: a country only counts as rare while it holds a tenth of one per
// cent of history, so an operator reached *only* there cannot have much history
// either. The two tests therefore never fight. What the distribution guard
// suppresses is always an operator seen in rare and ordinary countries both,
// which is precisely the shape of a content network and not of a destination
// somebody chose.
func TestRareDestinationStillReportsSingleCountryOperators(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 5000)

	add("IR", "One Place Hosting", "198.51.100.100", now.Add(-15*24*time.Hour))
	add("IR", "One Place Hosting", "198.51.100.101", now.Add(-14*24*time.Hour))
	add("IR", "One Place Hosting", "198.51.100.200", now.Add(-10*time.Minute))

	var found bool
	for _, o := range runRare(t, s, now) {
		if o.Detail["org"] == "One Place Hosting" {
			found = true
		}
	}
	if !found {
		t.Error("a destination reached in only one country should still be reported")
	}
}

// Three connections that happened to land in three countries is a coincidence,
// not a demonstration that an operator is distributed.
func TestRareDestinationDoesNotTrustATinySample(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	_, add := seedShape(t, s, now, 2000)

	for i, c := range []string{"NG", "PE", "KZ"} {
		add(c, "Barely Seen Ltd", "198.51.100."+itoaTest(120+i), now.Add(-15*24*time.Hour))
	}
	add("NG", "Barely Seen Ltd", "198.51.100.180", now.Add(-10*time.Minute))

	var found bool
	for _, o := range runRare(t, s, now) {
		if o.Detail["org"] == "Barely Seen Ltd" {
			found = true
		}
	}
	if !found {
		t.Error("a handful of connections should not qualify an operator as distributed")
	}
}
