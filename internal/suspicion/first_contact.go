package suspicion

import (
	"context"
	"fmt"
	"time"
)

// FirstContact notices a device talking to an organization it has never reached
// before.
//
// The obvious version of this rule is useless. A laptop meets new organizations
// constantly (every website, every CDN, every advertising network) so "new
// organization" on its own would fire hundreds of times a day and be correctly
// ignored.
//
// What makes it worth reporting is *who it happened to*. A thermostat that has
// spoken to two organizations in its life reaching a third is worth a look. A
// browser doing the same is Tuesday. So the score is a function of how unusual
// meeting somebody new is **for that particular device**, which is the network's
// own baseline rather than an assumption about what is normal.
type FirstContact struct{}

func (FirstContact) Code() string { return "first_contact" }

// Weight is low. On its own this is a weak signal by design; it earns its place
// by combining with others on the same subject.
func (FirstContact) Weight() float64 { return 0.35 }

// chattyThreshold is the number of distinct organizations per day above which a
// device is considered to meet new people routinely.
//
// Twelve is comfortably above what an appliance does and far below what a web
// browser does, which is the gap the rule lives in.
const chattyThreshold = 12.0

func (r FirstContact) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	// Nothing sensible to say about "never seen before" without a history to
	// have not seen it in.
	if in.Baseline < MinBaseline {
		return nil, nil
	}

	// The window is bounded at *both* ends. Without the upper bound a pass
	// evaluated at an earlier instant still sees everything that happened after
	// it, which made the test for "outside the window" pass for the wrong
	// reason: the broken gate below was excluding those rows, not the window.
	since := in.Now.Add(-in.Window).Unix()

	// **How long this device has been watched, not how long the install has.**
	//
	// This used to be in.Now.Add(-in.Baseline), and in.Baseline is time since
	// monitoring began, so the expression resolved to the install moment
	// exactly. A device's first contact cannot predate the first flow ever
	// recorded, so the gate below could only pass on the install second itself,
	// and never became true afterwards however long the install ran. The rule
	// produced nothing on a real network for three days and would have produced
	// nothing forever.
	//
	// What the rule actually needs is that *the device* has a history in which
	// it had not met this organization. A device first seen ten minutes ago has
	// no such history, and everything it does is a first contact; a day is
	// enough for the claim to mean something.
	deviceKnownSince := in.Now.Add(-MinBaseline).Unix()

	// For each device, the organizations first reached inside the window, plus
	// how many distinct organizations that device has ever reached. The second
	// number is what turns a fact into a judgement.
	rows, err := in.DB.QueryContext(ctx, `
-- Attribution prefers the device the capture source tagged the flow with, and
-- falls back to whichever device holds the source address.
--
-- The address join alone was discarding most of the data: a machine has many
-- local addresses (VPN tunnels, IPv6, bridges) and the Roster only knows the
-- one its neighbour table reported. On the development database that join saw
-- 4,175 of 27,251 flows, while every one of them carried a valid device_id.
WITH device_orgs AS (
  SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
         -- Only a real operator. This rule counts how many organizations a device
         -- has met, so falling back to a country made "first contact with
         -- Canada" a finding, and inflated the baseline with countries counted
         -- as organizations. An endpoint with no known operator is skipped by
         -- the empty check below rather than described as one.
         COALESCE(NULLIF(e.org, ''), '') AS org,
         MIN(f.ts_start) AS first_contact
  FROM flows f
  LEFT JOIN device_addresses a ON a.ip = f.src_ip
  JOIN endpoints e ON e.ip = f.dst_ip
  WHERE e.is_internal = 0
    AND f.established = 1
    AND COALESCE(NULLIF(e.org, ''), NULLIF(e.country, '')) IS NOT NULL
  GROUP BY COALESCE(NULLIF(f.device_id, ''), a.device_id, ''), org
),
totals AS (
  SELECT device_id, COUNT(*) AS org_count, MIN(first_contact) AS oldest
  FROM device_orgs GROUP BY device_id
)
SELECT d.device_id, d.org, d.first_contact, t.org_count, t.oldest
FROM device_orgs d
JOIN totals t ON t.device_id = d.device_id
WHERE d.first_contact >= ? AND d.first_contact <= ?
  -- The device has been watched long enough for "never before" to be a claim
  -- about the device rather than about the age of the database.
  AND t.oldest <= ?
ORDER BY d.first_contact DESC`, since, in.Now.Unix(), deviceKnownSince)
	if err != nil {
		return nil, fmt.Errorf("first contact query: %w", err)
	}
	defer rows.Close()

	var out []Observation
	for rows.Next() {
		var (
			deviceID, org        string
			firstContact, oldest int64
			orgCount             int
		)
		if err := rows.Scan(&deviceID, &org, &firstContact, &orgCount, &oldest); err != nil {
			return nil, err
		}
		if deviceID == "" || org == "" {
			continue
		}

		// How many organizations a day this device meets, over its own history.
		days := float64(in.Now.Unix()-oldest) / 86400
		if days < 1 {
			days = 1
		}
		rate := float64(orgCount) / days

		score := firstContactScore(rate)
		if score <= 0 {
			continue // a device that meets new people constantly is not news
		}

		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       score,
			At:          time.Unix(firstContact, 0),
			// Everything the sentence needs, and nothing it does not.
			Detail: map[string]any{
				"org":           org,
				"known_orgs":    orgCount,
				"orgs_per_day":  round1(rate),
				"observed_days": round1(days),
			},
			// The same device meeting the same organization is one finding,
			// however many connections it makes to it.
			Dedup: "first_contact:" + deviceID + ":" + org,
		})
	}
	return out, rows.Err()
}

// firstContactScore turns "how often this device meets someone new" into how
// much a new acquaintance is worth reporting.
//
// A device that has met four organizations in a month scores high; one that
// meets forty a day scores nothing at all. The curve is deliberately steep at
// the quiet end, because that is where the signal is.
func firstContactScore(orgsPerDay float64) float64 {
	if orgsPerDay >= chattyThreshold {
		return 0
	}
	// Linear from full score at "almost never" down to zero at the threshold.
	return Clamp(1 - orgsPerDay/chattyThreshold)
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
