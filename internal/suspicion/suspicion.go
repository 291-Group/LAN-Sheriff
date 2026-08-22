// Package suspicion is the rule engine behind the Wanted List.
//
// The design constraint that shapes everything here comes from the
// specification: every score must be explainable in plain language, and the
// engine stays rule-based rather than becoming a classifier. A finding nobody
// can check is a finding nobody should act on, and a tool that cries wolf gets
// ignored, at which point it is worse than absent, because it also provided
// false comfort.
//
// Three consequences run through this package:
//
//   - A rule reports *facts*, not prose. It emits the numbers and names that
//     make its case, and the dashboard turns them into a sentence in the
//     viewer's language. No English is ever stored.
//   - A rule must be able to recognise its own earlier work, so that running
//     every few minutes does not turn one event into a hundred findings.
//   - Scores are small and combine. A single weak signal should not reach the
//     top of the list on its own; several together should.
package suspicion

import (
	"context"
	"net/netip"
	"time"
)

// Observation is one rule's claim about one subject.
//
// Deliberately not a sentence. The rule supplies the evidence; the interface
// supplies the words, because the server cannot know what language the reader
// uses and English written into a database is untranslatable afterwards.
type Observation struct {
	// Subject is a device ID or an endpoint address.
	Subject     string
	SubjectType string
	// Score is this observation's contribution, from 0 to 1.
	Score float64
	// Detail carries the facts the explanation is built from, a count, an
	// interval, an organization name. Everything the sentence needs.
	Detail map[string]any
	// Dedup identifies *this* finding as distinct from other findings by the
	// same rule. Two observations sharing a dedup key are the same finding seen
	// again, not a new one.
	Dedup string
	// At is when the behaviour was observed, which is not always now: a rule
	// examining a window reports when the thing happened.
	At time.Time
}

// Rule is one thing worth noticing.
type Rule interface {
	// Code is the stable identifier stored with every finding and used as the
	// translation key. Renaming one rewrites history, so it does not change.
	Code() string
	// Weight scales this rule's observations when they are combined into a
	// subject's overall suspicion. A rule that fires often on ordinary traffic
	// carries less weight than one that almost never does.
	Weight() float64
	// Evaluate looks at the window ending at now and reports what it found.
	Evaluate(ctx context.Context, in Input) ([]Observation, error)
}

// Input is what a rule is given.
type Input struct {
	// DB is the read side of the store. Rules query; they never write.
	DB Queryer
	// Now is the end of the window under examination.
	Now time.Time
	// Window is how far back this pass looks.
	Window time.Duration
	// Baseline is how much history exists. A rule that needs to know what is
	// normal here must stay silent until there is enough of it to say.
	Baseline time.Duration
}

// Queryer is the narrow slice of the database a rule may use.
//
// Read-only by construction: a rule that could write would be able to influence
// the evidence the next rule sees, and the order rules ran in would start to
// matter.
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

// Rows is the subset of *sql.Rows rules need.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// MinBaseline is how much history must exist before rules that reason about
// "normal for this network" will say anything.
//
// A day. Everything is unusual to a database that started an hour ago, and a
// Wanted List full of a user's ordinary evening is the fastest way to teach them
// the feature is noise.
const MinBaseline = 24 * time.Hour

// Clamp keeps a score inside the range the rest of the engine assumes.
func Clamp(score float64) float64 {
	switch {
	case score < 0:
		return 0
	case score > 1:
		return 1
	}
	return score
}

// IsReportable reports whether a destination address is one worth reasoning
// about.
//
// The endpoints table cannot be trusted for this on its own. Its `is_internal`
// flag is only set once enrichment has reached an address, so a destination with
// no row yet reads as external, and on the development database that put
// `127.0.0.1`, with 187 connections, at the top of the beaconing candidates.
// A machine talking to itself is not command-and-control.
//
// So the address itself is checked, and the table is treated as an additional
// signal rather than the authority.
func IsReportable(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return false
	}
	// Carrier-grade NAT, which is the ISP's network rather than the user's, but
	// is not somewhere a device chooses to talk to either.
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return true
}
