package suspicion

import (
	"context"
	"fmt"
	"time"
)

// ThreatList notices a device looking up a domain that appears on a published
// list of known-malicious names.
//
// This is the most direct rule in the set, and the only one that is not
// statistical: every other rule reasons about what is normal *on this network*
// and needs history before it can say anything. A domain that somebody else has
// already identified as a malware command server does not become more malicious
// by being unusual here. So this rule needs no baseline at all and can fire on
// the first day.
//
// **It does need to see DNS lookups, which in practice means Patrol Mode.**
// Deputy Mode reads socket tables and reports a DNS feed only when this machine
// is itself serving DNS. On an ordinary Deputy install `dns_events` is empty and
// this rule is silent, not because nothing matched, but because there is
// nothing to match against. That is worth stating plainly rather than leaving a
// user to conclude their network is clean.
//
// **Only the malware category fires.** The same blocklist infrastructure labels
// advertising, tracking and telemetry domains, and it would be trivial to raise
// findings for those too. It would also be a mistake. An ordinary browser
// touches dozens of tracker domains an hour; a Wanted List that reported them
// would be a list of ordinary web browsing, and the one entry that mattered
// would be buried in it. Ad and tracker labels are shown inline in Radio Chatter
// where they are useful context, and are not findings.
//
// **A failed lookup still counts.** If the name did not resolve, because the
// domain has been taken down, or because something upstream is already blocking
// it, the device still asked for it. The question this rule answers is "did
// something here try to reach a known-bad host", and a query is the attempt.
// Whether it succeeded changes the urgency, not the fact.
//
// **The label is applied when the lookup is recorded, not when the rule runs.**
// Lookups observed before the lists were first fetched carry no label and are
// invisible here. That gap is bounded by the first successful fetch after
// install, and is preferable to re-labelling the entire history on every pass.
type ThreatList struct{}

func (ThreatList) Code() string { return "threat_list" }

// Weight is the highest of any rule. This is not an inference from behaviour,
// it is a name-for-name match against a list of hosts that other people have
// already caught doing harm.
func (ThreatList) Weight() float64 { return 0.95 }

const (
	// threatLookback is how far back a match stays interesting. Longer than the
	// other rules: contact with a known-bad host is worth surfacing days later,
	// whereas an unusual traffic volume is not.
	threatLookback = 7 * 24 * time.Hour

	// malwareCategory is the blocklist category this rule acts on. Kept as a
	// literal rather than importing internal/enrich, so that the rules package
	// stays dependency-free and testable against a bare database.
	malwareCategory = "malware"
)

func (r ThreatList) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	// No baseline check. See the type comment: this rule does not need to know
	// what is normal here.
	since := in.Now.Add(-threatLookback).Unix()

	// Grouped in SQL rather than in Go: the interesting output is one row per
	// device and domain however many times it was looked up, and there is no
	// reason to carry thousands of individual events across the boundary to
	// count them here.
	//
	// GROUP BY is positional. SQLite resolves a bare column name against the
	// output aliases before the input columns, which has silently grouped by the
	// wrong thing here before.
	rows, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(device_id, ''), qname, COUNT(*), MAX(ts),
       SUM(CASE WHEN answers IS NULL OR answers = '' OR answers = '[]' THEN 0 ELSE 1 END)
FROM dns_events
WHERE ts >= ? AND flagged = ?
GROUP BY 1, 2
ORDER BY 4 DESC`, since, malwareCategory)
	if err != nil {
		return nil, fmt.Errorf("threat list query: %w", err)
	}
	defer rows.Close()

	var out []Observation
	for rows.Next() {
		var (
			deviceID, qname string
			hits, resolved  int
			last            int64
		)
		if err := rows.Scan(&deviceID, &qname, &hits, &last, &resolved); err != nil {
			return nil, err
		}
		if deviceID == "" || qname == "" {
			continue
		}
		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       threatScore(hits, resolved > 0),
			At:          time.Unix(last, 0),
			Detail: map[string]any{
				"domain": qname,
				"hits":   hits,
				// Whether the name currently resolves, so the explanation can
				// distinguish "reached out to" from "tried to reach".
				"resolved": resolved > 0,
			},
			// One finding per device and domain. The same device contacting two
			// different bad hosts is two findings, because they are two
			// different things to go and look at.
			Dedup: "threat_list:" + deviceID + ":" + qname,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// threatScore rates a match.
//
// The floor is high and the range is narrow, because the finding is already
// near-certain before any of this is considered: the variation is between
// "serious" and "more serious", not between "maybe" and "yes". A name that
// resolves matters more than one that does not, and repeated lookups suggest
// something retrying rather than a single stray reference on a web page.
func threatScore(hits int, resolved bool) float64 {
	score := 0.75
	if resolved {
		score += 0.15
	}
	volume := float64(hits-1) / 20
	if volume > 1 {
		volume = 1
	}
	return Clamp(score + 0.10*volume)
}
