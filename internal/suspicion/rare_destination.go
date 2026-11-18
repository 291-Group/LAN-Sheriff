package suspicion

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RareDestination notices traffic to a part of the internet this network
// essentially never uses.
//
// The distinction from first contact matters. First contact asks "has this
// device met this organization before"; this asks "does this *network* go here
// at all". A household has a shape, a handful of countries, a few dozen
// hosting providers, and something reaching outside that shape is worth a
// glance even when the specific organization is new to nobody.
//
// The comparison is always against this network's own history. There is no list
// of suspicious countries and there will not be one: a Canadian household and a
// Japanese one have different normal, and a rule that shipped somebody's idea of
// a risky region would be both wrong and offensive.
type RareDestination struct{}

func (RareDestination) Code() string { return "rare_destination" }

// Weight sits between first contact and beaconing. Rare is meaningful but not
// damning, people travel, buy things abroad, and use services with unusual
// hosting.
func (RareDestination) Weight() float64 { return 0.5 }

const (
	// rareShareCeiling is the share of this network's history a destination's
	// country may hold and still count as rare. A tenth of one per cent.
	rareShareCeiling = 0.001

	// minHistoryForShares is how many connections must exist before a share is
	// a share rather than an accident of a small sample. Below this every
	// destination looks rare because everything does.
	minHistoryForShares = 500

	// distributedCountries is how many countries this network must already have
	// reached an organisation in before that organisation counts as globally
	// distributed, and a further country from it stops being news.
	//
	// **This is the difference between a rare place and a rare correspondent.**
	// A content network answers from whichever edge is closest, so a browser that
	// loads one ordinary page can touch Akamai in Australia, Google in Indonesia
	// and Amazon in Ireland without anything unusual happening. Reporting those
	// buried the one destination on a real network that deserved attention, a
	// single connection to a government host, under fifteen reports of CDNs
	// being CDNs.
	//
	// The test is deliberately *observed* rather than shipped. A built-in list of
	// content-network operators would need maintaining, would be wrong for
	// somebody whose provider is not on it, and would age badly (D14). Whether an
	// organisation is globally distributed is something this network's own
	// history already answers.
	distributedCountries = 3

	// minHitsForDistribution guards that test against a small sample: three
	// connections that happened to land in three countries is a coincidence, not
	// a demonstration of anything.
	minHitsForDistribution = 30
)

func (r RareDestination) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	if in.Baseline < MinBaseline {
		return nil, nil
	}
	since := in.Now.Add(-in.Window).Unix()

	// The network's shape: how much of its history each country accounts for,
	// alongside what was contacted inside the window.
	rows, err := in.DB.QueryContext(ctx, `
WITH totals AS (
  SELECT COUNT(*) AS n FROM flows f
  JOIN endpoints e ON e.ip = f.dst_ip
  WHERE e.is_internal = 0 AND f.established = 1 AND COALESCE(NULLIF(e.country, ''), '') != ''
),
org_spread AS (
  SELECT e.org AS org, COUNT(*) AS n, COUNT(DISTINCT e.country) AS countries
  FROM flows f JOIN endpoints e ON e.ip = f.dst_ip
  WHERE e.is_internal = 0 AND f.established = 1 AND COALESCE(NULLIF(e.org, ''), '') != ''
  GROUP BY e.org
),
by_country AS (
  SELECT e.country AS country, COUNT(*) AS n
  FROM flows f JOIN endpoints e ON e.ip = f.dst_ip
  WHERE e.is_internal = 0 AND f.established = 1 AND COALESCE(NULLIF(e.country, ''), '') != ''
  GROUP BY e.country
),
recent AS (
  SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
         e.country AS country,
         COALESCE(NULLIF(e.country_name, ''), e.country) AS country_name,
         COALESCE(NULLIF(e.org, ''), e.ip) AS org,
         COALESCE(NULLIF(e.org, ''), '') AS raw_org,
         e.ip AS addr,
         MAX(f.ts_last) AS last_seen,
         COUNT(*) AS hits
  FROM flows f
  LEFT JOIN device_addresses a ON a.ip = f.src_ip
  JOIN endpoints e ON e.ip = f.dst_ip
  WHERE f.ts_last >= ? AND f.established = 1 AND e.is_internal = 0
    AND COALESCE(NULLIF(e.country, ''), '') != ''
  GROUP BY COALESCE(NULLIF(f.device_id, ''), a.device_id, ''), e.country, org, raw_org, e.ip
)
SELECT r.device_id, r.country, r.country_name, r.org, r.addr, r.last_seen, r.hits,
       c.n, t.n
FROM recent r
JOIN by_country c ON c.country = r.country
LEFT JOIN org_spread s ON s.org = r.raw_org
CROSS JOIN totals t
WHERE t.n >= ?
  AND CAST(c.n AS REAL) / t.n <= ?
  -- An organisation this network already reaches in many countries is
  -- distributed, so a further country from it is an edge node answering.
  AND NOT (COALESCE(s.countries, 0) >= ? AND COALESCE(s.n, 0) >= ?)
ORDER BY r.last_seen DESC`,
		since, minHistoryForShares, rareShareCeiling,
		distributedCountries, minHitsForDistribution)
	if err != nil {
		return nil, fmt.Errorf("rare destination query: %w", err)
	}
	defer rows.Close()

	// **One finding per device, however many countries are involved.**
	//
	// The first version keyed on device and country, which is right when a
	// device reaches one unusual place and wrong when it reaches many: the
	// first router install had a workstation, a torrent client by the look of
	// it, talking to peers in 160 countries this network otherwise never
	// touched, and the Wanted List showed 160 findings for it, one per
	// country, each reading "0% of this network's traffic". A hundred and
	// sixty identical sentences say less than one that says "160 countries".
	// The query returns a row per address, because the address is needed to
	// check the destination is reportable at all, and everything folds up from
	// there: addresses into countries, countries into the device.
	type country struct {
		code, name, org string
		last            time.Time
		hits, total     int
		addresses       int
		share           float64
	}
	type device struct {
		countries map[string]*country
	}
	byDevice := map[string]*device{}
	var total int
	for rows.Next() {
		var (
			deviceID, code, countryName, org, addr string
			lastSeen                               int64
			hits, countryHits, n                   int
		)
		if err := rows.Scan(&deviceID, &code, &countryName, &org, &addr,
			&lastSeen, &hits, &countryHits, &n); err != nil {
			return nil, err
		}
		if deviceID == "" || !IsReportable(addr) {
			continue
		}
		total = n
		d, ok := byDevice[deviceID]
		if !ok {
			d = &device{countries: map[string]*country{}}
			byDevice[deviceID] = d
		}
		c, ok := d.countries[code]
		if !ok {
			c = &country{code: code, name: countryName, org: org,
				last: time.Unix(lastSeen, 0), hits: countryHits, total: n,
				share: float64(countryHits) / float64(n)}
			d.countries[code] = c
		}
		c.addresses++
		// The most recent address names the organisation shown.
		if at := time.Unix(lastSeen, 0); at.After(c.last) {
			c.last = at
			c.org = org
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Observation, 0, len(byDevice))
	for deviceID, d := range byDevice {
		// Most recent first, so the sentence leads with what just happened.
		list := make([]*country, 0, len(d.countries))
		for _, c := range d.countries {
			list = append(list, c)
		}
		sort.Slice(list, func(i, j int) bool {
			if !list[i].last.Equal(list[j].last) {
				return list[i].last.After(list[j].last)
			}
			return list[i].code < list[j].code
		})

		var (
			score     float64
			share     float64
			hits      int
			addresses int
			names     []string
		)
		for _, c := range list {
			score = max(score, rareScore(c.share))
			share += c.share
			hits += c.hits
			addresses += c.addresses
			if len(names) < 3 {
				names = append(names, c.name)
			}
		}
		// Many rare places at once is more notable than one, but not without
		// limit: a device reaching the whole world is one behaviour, not a
		// hundred.
		if n := len(list); n > 1 {
			score = Clamp(score + 0.05*float64(min(n-1, 4)))
		}
		first := list[0]
		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       score,
			At:          first.last,
			Detail: map[string]any{
				"country":      first.name,
				"country_code": first.code,
				"org":          first.org,
				"countries":    len(list),
				"examples":     strings.Join(names, ", "),
				"addresses":    addresses,
				"share_pct":    sharePct(share),
				"country_hits": hits,
				"total_hits":   total,
			},
			Dedup: "rare_destination:" + deviceID,
		})
	}
	// Stable order so a pass is reproducible.
	sort.Slice(out, func(i, j int) bool { return out[i].Dedup < out[j].Dedup })
	return out, nil
}

// sharePct is the share as a percentage for the sentence, to four decimal
// places rather than two: these are by definition tiny, and two places
// rendered every one of them as "0%", which read as a contradiction, a
// destination reached, accounting for nothing. A share too small even for
// four places shows as the smallest value that is not zero.
func sharePct(share float64) float64 {
	pct := float64(int(share*100*10000+0.5)) / 10000
	if pct == 0 && share > 0 {
		return 0.0001
	}
	return pct
}

// rareScore turns a share of the network's traffic into how notable it is.
//
// A destination holding a hundredth of a per cent of everything this network has
// ever done is more interesting than one holding a tenth of a per cent, and the
// curve reflects that rather than treating everything under the threshold alike.
func rareScore(share float64) float64 {
	if share >= rareShareCeiling {
		return 0
	}
	return Clamp(0.4 + 0.5*(1-share/rareShareCeiling))
}

// RareScoreForTest exposes the scoring curve so its shape can be checked
// independently of any fixture's size, which is what caused two tests to
// disagree with a correct implementation.
func RareScoreForTest(share float64) float64 { return rareScore(share) }
