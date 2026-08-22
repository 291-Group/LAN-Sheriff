package dispatch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The privacy decision, guarded the way the notification payload is: this shape
// is under permanent pressure to grow, and every addition would be individually
// defensible. A destination address or a hostname here would quietly turn an
// aggregate back into a flow log.
func TestSummaryBucketCarriesNothingItShouldNot(t *testing.T) {
	permitted := map[string]bool{
		"hour": true, "device": true,
		"endpoint_org": true, "endpoint_country": true, "asn": true,
		"app": true, "proto": true, "port": true,
		"flows": true, "bytes_out": true, "bytes_in": true,
	}

	typ := reflect.TypeOf(SummaryBucket{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if !permitted[name] {
			t.Errorf("SummaryBucket has a new field %q. A summary is an aggregate: "+
				"adding an address, hostname, path or fine-grained time turns it back "+
				"into a flow log. If this is deliberate, update the protocol document "+
				"and this test together.", name)
		}
	}

	// And nothing that looks like raw detail, whatever it is called.
	raw, err := json.Marshal(SummaryBucket{Hour: 1, Device: "d", Flows: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ip", "addr", "host", "path", "qname", "domain"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("a serialized bucket mentions %q", forbidden)
		}
	}
}

func now() time.Time { return time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC) }

func goodBucket() SummaryBucket {
	return SummaryBucket{
		Hour:   now().Add(-time.Hour).Truncate(time.Hour).Unix(),
		Device: "peer-device-1", Org: "Cloudflare, Inc.", Country: "US",
		ASN: 13335, App: "Firefox", Proto: "tcp", Port: 443, Flows: 42,
	}
}

func TestSanitizeKeepsGoodBuckets(t *testing.T) {
	msg := SummaryMessage{Buckets: []SummaryBucket{goodBucket()}}
	kept, dropped, err := msg.Sanitize(now())
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || dropped != 0 {
		t.Fatalf("kept %d dropped %d, want 1 and 0", len(kept), dropped)
	}
}

// One bad row must not discard a peer's whole report, or a single corrupt
// record would silence a machine.
func TestOneBadBucketDoesNotDiscardTheRest(t *testing.T) {
	bad := goodBucket()
	bad.Device = ""

	msg := SummaryMessage{Buckets: []SummaryBucket{goodBucket(), bad, goodBucket()}}
	kept, dropped, err := msg.Sanitize(now())
	if err != nil {
		t.Fatalf("a single malformed bucket produced a message-level error: %v", err)
	}
	if len(kept) != 2 || dropped != 1 {
		t.Errorf("kept %d dropped %d, want 2 and 1", len(kept), dropped)
	}
}

// Too many buckets is not one bad row, it is a peer ignoring the protocol.
func TestOversizedSummaryIsRejectedWholesale(t *testing.T) {
	buckets := make([]SummaryBucket, MaxBuckets+1)
	for i := range buckets {
		buckets[i] = goodBucket()
	}
	if _, _, err := (SummaryMessage{Buckets: buckets}).Sanitize(now()); err == nil {
		t.Fatal("a summary over the bucket limit was accepted")
	}

	exact := make([]SummaryBucket, MaxBuckets)
	for i := range exact {
		exact[i] = goodBucket()
	}
	if _, _, err := (SummaryMessage{Buckets: exact}).Sanitize(now()); err != nil {
		t.Errorf("a summary exactly at the limit was refused: %v", err)
	}
}

// A peer cannot backdate beneath a retention boundary, nor postdate to pin
// itself to the top of every time-ordered view.
func TestTimestampsOutsideTheWindowAreDropped(t *testing.T) {
	cases := map[string]time.Duration{
		"a week old":         -7 * 24 * time.Hour,
		"just too old":       -MaxBucketAge - time.Hour,
		"far in the future":  48 * time.Hour,
		"just too far ahead": MaxClockAhead + 2*time.Hour,
	}
	for name, offset := range cases {
		t.Run(name, func(t *testing.T) {
			b := goodBucket()
			b.Hour = now().Add(offset).Unix()

			kept, dropped, err := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
			if err != nil {
				t.Fatal(err)
			}
			if len(kept) != 0 || dropped != 1 {
				t.Errorf("kept %d dropped %d, want 0 and 1", len(kept), dropped)
			}
		})
	}
}

// The receiver re-truncates rather than trusting the sender to have done it.
func TestHourIsRetruncatedOnArrival(t *testing.T) {
	b := goodBucket()
	b.Hour = now().Add(-time.Hour).Unix() + 1847 // deliberately mid-hour

	kept, _, err := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 {
		t.Fatal("bucket dropped")
	}
	if kept[0].Hour%3600 != 0 {
		t.Errorf("hour %d is not truncated to an hour boundary", kept[0].Hour)
	}
}

// Negative counts are either a bug or an attempt to drag an aggregate down.
func TestNegativeCountsAreDropped(t *testing.T) {
	for name, mutate := range map[string]func(*SummaryBucket){
		"flows":     func(b *SummaryBucket) { b.Flows = -1 },
		"bytes out": func(b *SummaryBucket) { b.BytesOut = -5 },
		"bytes in":  func(b *SummaryBucket) { b.BytesIn = -5 },
	} {
		t.Run(name, func(t *testing.T) {
			b := goodBucket()
			mutate(&b)
			kept, dropped, _ := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
			if len(kept) != 0 || dropped != 1 {
				t.Errorf("kept %d dropped %d, want 0 and 1", len(kept), dropped)
			}
		})
	}
}

// A bucket describing nothing is not worth a row.
func TestEmptyBucketDropped(t *testing.T) {
	b := goodBucket()
	b.Flows, b.BytesOut, b.BytesIn = 0, 0, 0

	kept, dropped, _ := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	if len(kept) != 0 || dropped != 1 {
		t.Errorf("kept %d dropped %d, want 0 and 1", len(kept), dropped)
	}
}

// A peer controls these strings and they end up in a database and on a screen.
func TestOverlongFieldsAreBounded(t *testing.T) {
	b := goodBucket()
	b.Org = strings.Repeat("A", 10_000)
	b.App = strings.Repeat("B", 10_000)
	b.Device = strings.Repeat("C", 10_000)

	kept, dropped, _ := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	// An overlong device ID cannot be attributed safely, so the bucket goes.
	if len(kept) != 0 || dropped != 1 {
		t.Fatalf("an overlong device id was accepted: kept %d", len(kept))
	}

	b.Device = "ok-device"
	kept, _, _ = (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	if len(kept) != 1 {
		t.Fatal("bucket dropped")
	}
	if len(kept[0].Org) > maxOrgLen {
		t.Errorf("org is %d bytes, limit is %d", len(kept[0].Org), maxOrgLen)
	}
	if len(kept[0].App) > maxAppLen {
		t.Errorf("app is %d bytes, limit is %d", len(kept[0].App), maxAppLen)
	}
}

// Truncation must not split a rune: the result goes into a database and a UI.
func TestTruncationKeepsValidUTF8(t *testing.T) {
	b := goodBucket()
	// Multi-byte characters arranged so a naive cut lands mid-rune.
	b.Org = strings.Repeat("日", 200)

	kept, _, _ := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	if len(kept) != 1 {
		t.Fatal("bucket dropped")
	}
	if !utf8.ValidString(kept[0].Org) {
		t.Errorf("truncation produced invalid UTF-8: %q", kept[0].Org)
	}
	if len(kept[0].Org) > maxOrgLen {
		t.Errorf("org is %d bytes, over the limit", len(kept[0].Org))
	}
}

// Half a country code is a plausible-looking lie, so it is cleared rather than
// cut.
func TestOverlongCountryIsClearedNotTruncated(t *testing.T) {
	b := goodBucket()
	b.Country = "United States"

	kept, _, _ := (SummaryMessage{Buckets: []SummaryBucket{b}}).Sanitize(now())
	if len(kept) != 1 {
		t.Fatal("bucket dropped")
	}
	if kept[0].Country != "" {
		t.Errorf("country = %q, want it cleared rather than cut to %q",
			kept[0].Country, kept[0].Country)
	}
}
