package dispatch

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Messages on the wire. See docs/DISPATCH-PROTOCOL.md §7.
//
// Every message is a JSON object in one frame. The envelope carries a version
// and a type; the body is whatever that type defines.
//
// Two forward-compatibility rules, and they point in opposite directions on
// purpose:
//
//   - **Unknown fields are ignored.** A newer peer may add fields, and an older
//     build must keep working rather than refusing a message it mostly
//     understands.
//   - **Unknown protocol versions are refused.** A version is a statement that
//     the framing or semantics changed, and guessing at that is how a security
//     protocol acquires a downgrade attack.

// ProtocolVersion is the wire generation this build speaks.
const ProtocolVersion = 1

// Message types.
const (
	TypeHello   = "hello"
	TypeSummary = "summary"
	TypeFinding = "finding"
	TypeDevice  = "device"
	TypePing    = "ping"
	TypePong    = "pong"
	TypeBye     = "bye"
)

// Envelope wraps every message.
type Envelope struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

var (
	// ErrWrongVersion is returned for a message from another protocol
	// generation. The connection should be closed: there is no downgrade path.
	ErrWrongVersion = errors.New("dispatch: message is from a different protocol version")

	// ErrUnknownType is returned for a type this build does not implement. The
	// caller logs and continues, the connection stays up, since an unknown
	// message is how a newer peer adds a feature.
	ErrUnknownType = errors.New("dispatch: unknown message type")

	// ErrMalformed covers anything that is not valid JSON or not the shape the
	// type requires.
	ErrMalformed = errors.New("dispatch: malformed message")
)

// knownTypes is the set this build implements.
var knownTypes = map[string]bool{
	TypeHello: true, TypeSummary: true, TypeFinding: true,
	TypeDevice: true, TypePing: true, TypePong: true, TypeBye: true,
	TypePairRequest: true, TypePairResponse: true,
}

// EncodeMessage marshals a message body into a frame payload.
func EncodeMessage(msgType string, body any) ([]byte, error) {
	if !knownTypes[msgType] {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, msgType)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("dispatch: encoding %s body: %w", msgType, err)
	}
	return json.Marshal(Envelope{V: ProtocolVersion, Type: msgType, Body: raw})
}

// DecodeEnvelope reads the envelope of a received frame.
//
// It deliberately does not decode the body: the caller dispatches on the type
// first, so a body is only ever parsed by code that knows what shape it should
// be. A single decode into a union type would mean every message allocating
// every field.
func DecodeEnvelope(payload []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.V != ProtocolVersion {
		return Envelope{}, fmt.Errorf("%w: peer speaks v%d, this build speaks v%d",
			ErrWrongVersion, env.V, ProtocolVersion)
	}
	if env.Type == "" {
		return Envelope{}, fmt.Errorf("%w: message has no type", ErrMalformed)
	}
	if !knownTypes[env.Type] {
		return env, fmt.Errorf("%w: %q", ErrUnknownType, env.Type)
	}
	return env, nil
}

// DecodeBody parses an envelope's body into a typed value.
func DecodeBody[T any](env Envelope) (T, error) {
	var out T
	if len(env.Body) == 0 {
		return out, fmt.Errorf("%w: %s has no body", ErrMalformed, env.Type)
	}
	if err := json.Unmarshal(env.Body, &out); err != nil {
		return out, fmt.Errorf("%w: %s body: %v", ErrMalformed, env.Type, err)
	}
	return out, nil
}

// Hello is the first message in both directions.
type Hello struct {
	PeerID string `json:"peer_id"`
	// Label is what the sender calls itself, sent on every connection rather
	// than only at pairing so that a machine renamed later is renamed for its
	// peers too, and so a pairing made before this field existed still ends up
	// with a name instead of a fingerprint. Display only: the receiver keeps
	// any name its own operator chose.
	Label string `json:"label,omitempty"`
	// Software is this build's version string, for display only. It is never
	// used to decide behaviour: a peer that lies about its version must not be
	// able to steer us into a different code path.
	Software string `json:"software"`
	// Clock is the sender's wall clock in Unix seconds, so skew can be reported
	// rather than silently corrected.
	Clock int64 `json:"clock"`
	// Capabilities names what the peer can observe, so its absence of data can
	// be explained rather than displayed as silence.
	Mode string `json:"mode"`
	// ListenPort is where the sender accepts peer connections.
	//
	// Only the port, deliberately. The address a peer can be reached at is taken
	// from the connection we are already holding; a peer that could name a *host*
	// could point us at a third party, which is a redirect primitive handed to
	// the one participant the merge rules already assume may be compromised.
	// A port is the minimum needed to dial back and cannot redirect anything.
	ListenPort int `json:"listen_port,omitempty"`
}

// Bye is an orderly close. Advisory only: a connection may vanish without one,
// and the code must handle both identically.
type Bye struct {
	Reason string `json:"reason"`
}

// Ping and Pong carry a nonce so a reply can be matched to its request, and the
// sender's clock so skew is measured continuously rather than only at hello.
type Ping struct {
	Nonce int64 `json:"nonce"`
	Clock int64 `json:"clock"`
}

// Pong echoes a Ping.
type Pong struct {
	Nonce int64 `json:"nonce"`
	Clock int64 `json:"clock"`
}
