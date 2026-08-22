package suspicion

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// DGADomain notices a device looking up several machine-generated domain names
// that do not exist.
//
// Malware that cannot hard-code its command server generates candidate names
// from a seed and tries them until one answers. The give-away is not any single
// name, it is a burst of failures across unrelated nonsense.
//
// **Entropy alone would be useless here, and worse than useless.** Modern
// content delivery is full of legitimately random-looking hostnames:
// `d3n8a8pro7vhmx.cloudfront.net`, hashed bucket names, per-session subdomains.
// A rule that flagged high entropy would fire on ordinary browsing all day.
//
// Three things are required together:
//
//  1. **The registrable domain looks generated**, not the subdomain. CDN
//     randomness lives in the labels *below* a recognisable parent; generated
//     domains are random at the registrable level itself.
//  2. **The lookup failed.** A name that resolves is somebody's real service,
//     however odd it looks. A name that does not is a guess, and guessing is
//     the whole technique.
//  3. **Several of them, from one device, close together.** One failed lookup
//     of a strange name is a typo or a dead link.
type DGADomain struct{}

func (DGADomain) Code() string { return "dga_domain" }

// Weight is high. Unlike a rare destination, there is no ordinary reason for a
// device to be guessing domain names.
func (DGADomain) Weight() float64 { return 0.85 }

const (
	// dgaLookback is how long a burst may be spread over and still count as one.
	dgaLookback = 6 * time.Hour

	// minDGAHits is how many failed generated-looking lookups make a pattern.
	// One is a typo; two is a coincidence.
	minDGAHits = 5

	// minDGAScore is how generated a name must look, from looksGenerated.
	minDGAScore = 0.6
)

func (r DGADomain) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	if in.Baseline < MinBaseline {
		return nil, nil
	}
	since := in.Now.Add(-dgaLookback).Unix()

	// Only lookups that returned nothing. An answered query is somebody's real
	// service, whatever its name looks like.
	rows, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(device_id, ''), qname, ts
FROM dns_events
WHERE ts >= ?
  AND (answers IS NULL OR answers = '' OR answers = '[]')
ORDER BY device_id, ts`, since)
	if err != nil {
		return nil, fmt.Errorf("dga query: %w", err)
	}
	defer rows.Close()

	type acc struct {
		names  []string
		last   int64
		scores float64
	}
	byDevice := map[string]*acc{}

	for rows.Next() {
		var (
			deviceID, qname string
			ts              int64
		)
		if err := rows.Scan(&deviceID, &qname, &ts); err != nil {
			return nil, err
		}
		if deviceID == "" {
			continue
		}
		reg := registrableDomain(qname)
		if reg == "" {
			continue
		}
		score := looksGenerated(reg)
		if score < minDGAScore {
			continue
		}

		a := byDevice[deviceID]
		if a == nil {
			a = &acc{}
			byDevice[deviceID] = a
		}
		// The same name tried repeatedly is one guess, not several.
		if !containsString(a.names, reg) {
			a.names = append(a.names, reg)
			a.scores += score
		}
		if ts > a.last {
			a.last = ts
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []Observation
	for deviceID, a := range byDevice {
		if len(a.names) < minDGAHits {
			continue
		}
		sample := a.names
		if len(sample) > 3 {
			sample = sample[:3]
		}
		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       dgaScore(len(a.names), a.scores/float64(len(a.names))),
			At:          time.Unix(a.last, 0),
			Detail: map[string]any{
				"names":   len(a.names),
				"example": strings.Join(sample, ", "),
			},
			// One burst per device. A device that keeps guessing is still one
			// finding, refreshed.
			Dedup: "dga_domain:" + deviceID,
		})
	}
	return out, nil
}

// dgaScore rates a burst by how many distinct guesses it contains and how
// generated they look.
func dgaScore(names int, avgLook float64) float64 {
	volume := float64(names-minDGAHits) / 25
	if volume > 1 {
		volume = 1
	}
	return Clamp(0.6 + 0.25*volume + 0.15*(avgLook-minDGAScore)/(1-minDGAScore))
}

// registrableDomain reduces a name to the part somebody registered.
//
// Deliberately approximate: this is not a public-suffix implementation, and does
// not need to be. What matters is stripping the subdomain labels where content
// delivery puts its randomness, so that `d3n8a8pro7vhmx.cloudfront.net` is
// judged as `cloudfront.net`, which looks entirely ordinary, because it is.
func registrableDomain(qname string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if name == "" || strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".arpa") {
		return ""
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return ""
	}
	// Two-level public suffixes that would otherwise leave only the suffix.
	if len(parts) >= 3 && twoLevelSuffixes[parts[len(parts)-2]+"."+parts[len(parts)-1]] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

var twoLevelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "or.jp": true, "ne.jp": true,
	"com.br": true, "com.cn": true, "com.mx": true, "co.in": true,
	"co.nz": true, "co.za": true, "com.tr": true, "com.sg": true,
}

// looksGenerated rates how much a registrable domain resembles something a
// program produced rather than something a person chose.
//
// Three signals, because any one alone is wrong often enough to be useless:
// character entropy, the proportion of vowels, and how much of the label is
// digits. A person's domain is pronounceable; a generated one usually is not.
func looksGenerated(domain string) float64 {
	label := domain
	if i := strings.Index(domain, "."); i > 0 {
		label = domain[:i]
	}
	// Short names are not distinguishable either way, and long ones are where
	// generators live.
	if len(label) < 8 {
		return 0
	}

	entropy := shannon(label)
	// Roughly: 3.0 bits is ordinary English-ish, 4.0+ is close to random over
	// the alphabet.
	entropyScore := Clamp((entropy - 2.9) / 1.1)

	vowels := 0
	digits := 0
	for _, r := range label {
		switch {
		case strings.ContainsRune("aeiou", r):
			vowels++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	vowelRatio := float64(vowels) / float64(len(label))
	// English words run around 38% vowels; below 25% is hard to pronounce.
	vowelScore := Clamp((0.32 - vowelRatio) / 0.22)
	digitScore := Clamp(float64(digits) / float64(len(label)) / 0.4)

	return Clamp(0.5*entropyScore + 0.35*vowelScore + 0.15*digitScore)
}

// shannon returns the entropy of a string in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
