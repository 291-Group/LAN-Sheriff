package dispatch

import (
	"errors"
	"strings"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	payload, err := EncodeMessage(TypeHello, Hello{
		PeerID: "ABCDE12345ABCDE12345ABCDE", Software: "v.1.9.9PRB",
		Clock: 1753977600, Mode: "deputy",
	})
	if err != nil {
		t.Fatal(err)
	}

	env, err := DecodeEnvelope(payload)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != TypeHello || env.V != ProtocolVersion {
		t.Fatalf("envelope = %+v", env)
	}

	body, err := DecodeBody[Hello](env)
	if err != nil {
		t.Fatal(err)
	}
	if body.PeerID != "ABCDE12345ABCDE12345ABCDE" || body.Mode != "deputy" {
		t.Errorf("body = %+v", body)
	}
}

// A newer peer must be able to add fields without breaking this build.
func TestUnknownFieldsAreIgnored(t *testing.T) {
	raw := []byte(`{"v":1,"type":"hello","body":{"peer_id":"X","mode":"patrol",
	                "something_added_later":{"nested":true}},"extra":42}`)

	env, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatalf("an envelope with an unknown field was refused: %v", err)
	}
	body, err := DecodeBody[Hello](env)
	if err != nil {
		t.Fatalf("a body with an unknown field was refused: %v", err)
	}
	if body.Mode != "patrol" {
		t.Errorf("known fields were lost: %+v", body)
	}
}

// A version is a statement that framing or semantics changed. Guessing at that
// is how a protocol acquires a downgrade attack.
func TestOtherVersionsAreRefused(t *testing.T) {
	for _, raw := range []string{
		`{"v":0,"type":"hello","body":{}}`,
		`{"v":2,"type":"hello","body":{}}`,
		`{"type":"hello","body":{}}`,
	} {
		if _, err := DecodeEnvelope([]byte(raw)); !errors.Is(err, ErrWrongVersion) {
			t.Errorf("DecodeEnvelope(%s) error = %v, want ErrWrongVersion", raw, err)
		}
	}
}

// An unknown type is how a newer peer adds a feature: log and carry on, rather
// than dropping a connection that is otherwise healthy.
func TestUnknownTypeIsDistinguishable(t *testing.T) {
	env, err := DecodeEnvelope([]byte(`{"v":1,"type":"telemetry","body":{}}`))
	if !errors.Is(err, ErrUnknownType) {
		t.Fatalf("error = %v, want ErrUnknownType", err)
	}
	// The envelope is still returned so a caller can log what it was.
	if env.Type != "telemetry" {
		t.Errorf("envelope type = %q, want it preserved for logging", env.Type)
	}
}

func TestMalformedMessages(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":      `{oh dear`,
		"not an object": `["v",1]`,
		"no type":       `{"v":1,"body":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEnvelope([]byte(raw)); err == nil {
				t.Errorf("DecodeEnvelope(%s) succeeded", raw)
			}
		})
	}
}

func TestEncodeRefusesUnknownType(t *testing.T) {
	if _, err := EncodeMessage("exfiltrate", struct{}{}); !errors.Is(err, ErrUnknownType) {
		t.Errorf("error = %v, want ErrUnknownType", err)
	}
}

func TestDecodeBodyRequiresABody(t *testing.T) {
	env, err := DecodeEnvelope([]byte(`{"v":1,"type":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBody[Ping](env); !errors.Is(err, ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// A message must fit a frame, which is what makes the two limits consistent.
func TestAFullSummaryFitsInAFrame(t *testing.T) {
	buckets := make([]SummaryBucket, MaxBuckets)
	for i := range buckets {
		buckets[i] = SummaryBucket{
			Hour: 1753977600, Device: strings.Repeat("d", maxDeviceIDLen),
			Org: strings.Repeat("O", maxOrgLen), Country: "US", ASN: 4294967,
			App: strings.Repeat("A", maxAppLen), Proto: "tcp", Port: 65535,
			Flows: 1 << 40, BytesOut: 1 << 40, BytesIn: 1 << 40,
		}
	}
	payload, err := EncodeMessage(TypeSummary, SummaryMessage{Buckets: buckets})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxFrameSize {
		t.Errorf("a maximal summary is %d bytes, over the %d-byte frame limit; "+
			"MaxBuckets and MaxFrameSize disagree", len(payload), MaxFrameSize)
	}
	t.Logf("worst-case summary: %d bytes of %d", len(payload), MaxFrameSize)
}
