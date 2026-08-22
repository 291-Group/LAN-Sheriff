package suspicion

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Beaconing notices a device contacting the same destination at a regular
// interval.
//
// This is the rule that can actually catch command-and-control traffic, and it
// is also the rule most likely to be wrong in a way that ruins the product. A
// home network is full of things that talk on a timer: NTP, update checkers,
// push-notification keepalives, telemetry, a thermostat reporting temperature.
// A rule that reports all of them is a rule that gets switched off.
//
// Three things separate a beacon from a heartbeat, and all three are required:
//
//  1. **Regularity far beyond what human-driven traffic produces.** Software on
//     a timer is regular; malware on a timer is *very* regular. The measure is
//     robust to a single missed or delayed connection, because one hiccup should
//     not clear an otherwise perfect rhythm.
//  2. **An interval in a band that matters.** Below twenty seconds is a
//     keepalive on an open session. Above the observation window there are not
//     enough repetitions to call it a rhythm rather than a coincidence.
//  3. **Enough repetitions to mean something.** Three connections at similar
//     spacing is an accident; a dozen is a schedule.
//
// Even then the finding says what it saw, this destination, this interval, this
// many times, and leaves the judgement legible. Plenty of legitimate software
// beacons, and the honest thing is to show the rhythm and let the user recognise
// their own thermostat.
type Beaconing struct{}

func (Beaconing) Code() string { return "beaconing" }

// Weight is high. Unlike first contact, a tight rhythm is rare in ordinary
// traffic, so when this fires it deserves attention.
func (Beaconing) Weight() float64 { return 0.8 }

const (
	// beaconLookback is how far back this rule looks, independent of the pass
	// window. A rhythm cannot be established in two hours: at a ten-minute
	// interval that is twelve repetitions, and at an hourly interval it is two.
	beaconLookback = 12 * time.Hour

	// minBeaconHits is how many connections are needed before spacing counts as
	// a schedule rather than a coincidence.
	minBeaconHits = 8

	// minBeaconInterval excludes keepalives on a long-lived session, which are
	// regular by design and say nothing.
	minBeaconInterval = 20 * time.Second

	// maxBeaconInterval keeps the rhythm inside what the lookback can actually
	// witness several times over.
	maxBeaconInterval = 90 * time.Minute

	// minRegularity is how tight the rhythm must be. Expressed as
	// 1 - (spread / interval), so 0.85 means the typical deviation is under
	// fifteen per cent of the interval, tighter than almost anything a person
	// causes, and looser than a beacon with jitter.
	minRegularity = 0.85
)

func (r Beaconing) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	if in.Baseline < MinBaseline {
		return nil, nil
	}
	since := in.Now.Add(-beaconLookback).Unix()

	// Only pairs with enough connections to be worth measuring. Filtering in SQL
	// keeps the scan small: most destinations are contacted once or twice.
	rows, err := in.DB.QueryContext(ctx, `
-- Attribution prefers the device the capture source tagged the flow with, and
-- falls back to whichever device holds the source address.
--
-- The address join alone was discarding most of the data: a machine has many
-- local addresses (VPN tunnels, IPv6, bridges) and the Roster only knows the
-- one its neighbour table reported. On the development database that join saw
-- 4,175 of 27,251 flows, while every one of them carried a valid device_id.
SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id, f.dst_ip,
       -- No country fallback. An endpoint with no known operator reported as its
       -- country produced findings reading "connected to Canada every 20
       -- minutes", which states something false about an organization. The
       -- address says "we do not know who owns this", which is true.
       COALESCE(NULLIF(e.org, ''), f.dst_ip) AS org,
       f.ts_start
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
LEFT JOIN endpoints e ON e.ip = f.dst_ip
WHERE f.ts_start >= ?
  AND f.established = 1
  AND COALESCE(e.is_internal, 0) = 0
  AND (COALESCE(NULLIF(f.device_id, ''), a.device_id, ''), f.dst_ip) IN (
    SELECT COALESCE(NULLIF(f2.device_id, ''), a2.device_id), f2.dst_ip
    FROM flows f2
    LEFT JOIN device_addresses a2 ON a2.ip = f2.src_ip
    WHERE f2.ts_start >= ? AND f2.established = 1
    GROUP BY 1, 2
    HAVING COUNT(*) >= ?
  )
ORDER BY 1, f.dst_ip, f.ts_start`, since, since, minBeaconHits)
	if err != nil {
		return nil, fmt.Errorf("beaconing query: %w", err)
	}
	defer rows.Close()

	type key struct{ device, dst string }
	times := map[key][]int64{}
	orgs := map[key]string{}

	for rows.Next() {
		var (
			device, dst, org string
			ts               int64
		)
		if err := rows.Scan(&device, &dst, &org, &ts); err != nil {
			return nil, err
		}
		if device == "" {
			continue
		}
		// The endpoints table's is_internal flag is unset until enrichment
		// reaches an address, so the address itself is the authority here.
		if !IsReportable(dst) {
			continue
		}
		k := key{device, dst}
		times[k] = append(times[k], ts)
		orgs[k] = org
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// **One finding per device and destination *service*, not per address.**
	//
	// A rhythm is measured per address (each connection has its own timing) but
	// a service is not one address. Tailscale's relays, a CDN and anything behind
	// anycast all answer on many, and keying the finding on the address produced
	// one row per address: on a real network, 55 beaconing findings that were
	// really six services, 27 of them the same one. A Wanted List with 74 rows
	// for a single device is a list nobody reads, which costs the other rules
	// their credibility too.
	//
	// Grouping by organization works cleanly because an endpoint with no known
	// operator already reports its address as its org, so unattributed
	// destinations stay separate, exactly as they should.
	type group struct {
		addresses  int
		hits       int
		interval   time.Duration
		regularity float64
		last       int64
	}
	groups := map[key]*group{}

	for k, ts := range times {
		interval, regularity, ok := rhythm(ts)
		if !ok {
			continue
		}
		// The org stands in for the destination; k.dst is kept only when there
		// is no org to speak of, which the query already guarantees.
		gk := key{k.device, orgs[k]}
		g := groups[gk]
		if g == nil {
			g = &group{}
			groups[gk] = g
		}
		g.addresses++
		g.hits += len(ts)
		if last := ts[len(ts)-1]; last > g.last {
			g.last = last
		}
		// The clearest rhythm represents the service. Averaging intervals across
		// addresses would invent a cadence that nothing actually keeps.
		if regularity > g.regularity {
			g.regularity, g.interval = regularity, interval
		}
	}

	var out []Observation
	for gk, g := range groups {
		out = append(out, Observation{
			Subject:     gk.device,
			SubjectType: "device",
			Score:       beaconScore(g.regularity, g.hits),
			At:          time.Unix(g.last, 0),
			Detail: map[string]any{
				"org":           gk.dst,
				"addresses":     g.addresses,
				"interval_secs": int(g.interval.Seconds()),
				"hits":          g.hits,
				"regularity":    round1(g.regularity * 100),
			},
			Dedup: "beaconing:" + gk.device + ":" + gk.dst,
		})
	}
	// Stable order so a pass is reproducible and the tests are not flaky.
	sort.Slice(out, func(i, j int) bool { return out[i].Dedup < out[j].Dedup })
	return out, nil
}

// rhythm measures the spacing of a series of connection times.
//
// Uses the median interval and the median absolute deviation rather than mean
// and standard deviation. That choice matters: one missed connection doubles a
// single gap, and with a mean-based measure that single outlier is enough to
// hide an otherwise perfect rhythm, which is exactly the case worth catching,
// since real beacons miss occasionally.
func rhythm(ts []int64) (interval time.Duration, regularity float64, ok bool) {
	if len(ts) < minBeaconHits {
		return 0, 0, false
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })

	gaps := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		g := float64(ts[i] - ts[i-1])
		// Connections in the same instant are one event observed twice, not a
		// rhythm of zero.
		if g <= 0 {
			continue
		}
		gaps = append(gaps, g)
	}
	if len(gaps) < minBeaconHits-1 {
		return 0, 0, false
	}

	med := median(gaps)
	if med < minBeaconInterval.Seconds() || med > maxBeaconInterval.Seconds() {
		return 0, 0, false
	}

	deviations := make([]float64, len(gaps))
	for i, g := range gaps {
		deviations[i] = abs(g - med)
	}
	spread := median(deviations)

	regularity = 1 - spread/med
	if regularity < minRegularity {
		return 0, 0, false
	}
	return time.Duration(med) * time.Second, regularity, true
}

// beaconScore rates a rhythm by how tight it is and how long it has persisted.
//
// Both matter: a very tight rhythm seen nine times is interesting, and a
// slightly looser one seen two hundred times is interesting for a different
// reason.
func beaconScore(regularity float64, hits int) float64 {
	// Regularity from the threshold to perfect, mapped across most of the range.
	tightness := (regularity - minRegularity) / (1 - minRegularity)
	persistence := float64(hits-minBeaconHits) / 40
	if persistence > 1 {
		persistence = 1
	}
	return Clamp(0.55 + 0.3*tightness + 0.15*persistence)
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
