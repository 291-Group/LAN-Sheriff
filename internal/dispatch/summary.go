package dispatch

import (
	"fmt"
	"time"
)

// Summaries: the per-bucket aggregates peers exchange instead of raw flows.
// See docs/DISPATCH-PROTOCOL.md §D-5 and §8.
//
// The privacy argument for aggregating is the whole reason this shape exists. A
// raw flow log is a minute-by-minute record of somebody's evening. An hourly
// aggregate against an organization and a country is what the Watchtower
// actually draws. Peers exchange the second and never the first.
//
// Note what a bucket does **not** carry: no destination address, no hostname, no
// process path, and no timestamp finer than the hour. A test asserts that, in
// the same spirit as the notification payload's, this shape is under permanent
// pressure to grow, and each addition would be individually defensible.

const (
	// MaxBuckets caps one summary message.
	//
	// Derived from MaxFrameSize rather than chosen: a bucket with every string
	// at its limit encodes to about 562 bytes, so 1,500 of them is roughly 74%
	// of a frame. The first draft said 5,000, which is 247% of a frame, a peer
	// sending a legitimately maximal summary would have been disconnected for
	// oversizing it. A test encodes the worst case and fails if these two
	// constants ever disagree again.
	//
	// A sender with more than this to report sends several messages. Buckets are
	// keyed and upserted, so splitting a report changes nothing downstream.
	MaxBuckets = 1500

	// MaxBucketAge is how far back a peer may report. Anything older is
	// discarded rather than clamped: a peer sending week-old buckets is
	// confused, and quietly filing them under a wrong hour would be worse than
	// dropping them.
	MaxBucketAge = 48 * time.Hour

	// MaxClockAhead is how far into the future a peer's timestamp may sit before
	// it is treated as skew. Small, because the damage from a future timestamp
	// is that it pins itself to the top of every time-ordered view.
	MaxClockAhead = 5 * time.Minute
)

// SummaryBucket is one hour of one device's traffic to one organization.
type SummaryBucket struct {
	// Hour is the start of the hour, Unix seconds. Truncated by the sender and
	// re-truncated by the receiver, since a sender's truncation is not something
	// to take on trust.
	Hour int64 `json:"hour"`
	// Device is the reporting peer's own device identifier. It is namespaced
	// under that peer on arrival and is never matched against local device IDs.
	Device string `json:"device"`

	Org     string `json:"endpoint_org,omitempty"`
	Country string `json:"endpoint_country,omitempty"`
	ASN     int    `json:"asn,omitempty"`

	App   string `json:"app,omitempty"`
	Proto string `json:"proto,omitempty"`
	Port  uint16 `json:"port,omitempty"`

	Flows    int64 `json:"flows"`
	BytesOut int64 `json:"bytes_out,omitempty"`
	BytesIn  int64 `json:"bytes_in,omitempty"`
}

// SummaryMessage is the body of a TypeSummary message.
type SummaryMessage struct {
	Buckets []SummaryBucket `json:"buckets"`
}

// Field length limits. A peer controls these strings, and they end up in a
// database and on a screen; an organization name is not a place to accept four
// kilobytes.
const (
	maxDeviceIDLen = 64
	maxOrgLen      = 128
	maxCountryLen  = 2
	maxAppLen      = 128
	maxProtoLen    = 8
)

// Sanitize validates a received summary and returns the buckets worth keeping.
//
// It **never** returns an error for an individual bad bucket: a peer with one
// malformed row should not have its whole report discarded, and disconnecting
// over it would let a single corrupt record silence a machine. Buckets that
// cannot be trusted are dropped and counted, so the caller can log a peer that
// is producing many of them.
//
// It does return an error for a message that is structurally unreasonable,
// more buckets than the protocol permits, because that is not one bad row, it
// is a peer ignoring the protocol.
func (m SummaryMessage) Sanitize(now time.Time) (kept []SummaryBucket, dropped int, err error) {
	if len(m.Buckets) > MaxBuckets {
		return nil, 0, fmt.Errorf("dispatch: summary carries %d buckets, limit is %d",
			len(m.Buckets), MaxBuckets)
	}

	oldest := now.Add(-MaxBucketAge).Unix()
	newest := now.Add(MaxClockAhead).Unix()

	kept = make([]SummaryBucket, 0, len(m.Buckets))
	for _, b := range m.Buckets {
		clean, ok := b.sanitize(oldest, newest)
		if !ok {
			dropped++
			continue
		}
		kept = append(kept, clean)
	}
	return kept, dropped, nil
}

// sanitize checks and normalizes one bucket.
func (b SummaryBucket) sanitize(oldest, newest int64) (SummaryBucket, bool) {
	// A bucket about no device cannot be attributed, and attribution is the
	// whole basis of the merge rules.
	if b.Device == "" || len(b.Device) > maxDeviceIDLen {
		return SummaryBucket{}, false
	}
	// Outside the window entirely. Dropped rather than clamped: see MaxBucketAge.
	if b.Hour < oldest || b.Hour > newest {
		return SummaryBucket{}, false
	}
	// Counts are unsigned in meaning. A negative one is either a bug or an
	// attempt to drag an aggregate downwards, and neither should be stored.
	if b.Flows < 0 || b.BytesOut < 0 || b.BytesIn < 0 {
		return SummaryBucket{}, false
	}
	// A bucket describing nothing is not worth a row.
	if b.Flows == 0 && b.BytesOut == 0 && b.BytesIn == 0 {
		return SummaryBucket{}, false
	}

	// Re-truncate rather than trusting the sender to have done it.
	b.Hour = b.Hour - b.Hour%3600

	b.Org = truncate(b.Org, maxOrgLen)
	b.App = truncate(b.App, maxAppLen)
	b.Proto = truncate(b.Proto, maxProtoLen)
	if len(b.Country) > maxCountryLen {
		// Not truncated: a country code is either the two letters or it is not a
		// country code, and half of one would be a plausible-looking lie.
		b.Country = ""
	}
	if b.ASN < 0 {
		b.ASN = 0
	}
	return b, true
}

// truncate cuts a string to a byte budget without splitting a rune.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Back off to a rune boundary so the result is still valid UTF-8, it is
	// going into a database and onto a screen.
	for max > 0 && !utf8Start(s[max]) {
		max--
	}
	return s[:max]
}

// utf8Start reports whether b begins a UTF-8 sequence.
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
