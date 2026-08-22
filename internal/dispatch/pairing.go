package dispatch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Pairing: the only moment trust is created out of nothing.
// docs/DISPATCH-PROTOCOL.md §5.
//
// The exchange is short and every step of it is load-bearing:
//
//  1. The joiner connects. TLS completes, but nothing is trusted yet.
//  2. The joiner checks the presented key against the tag in the code, and
//     aborts on a mismatch **before disclosing anything**. This is what denies
//     an on-path attacker a proof to grind offline.
//  3. Both sides derive a binding from the completed TLS session.
//  4. The joiner proves knowledge of the secret over that binding.
//  5. The displayer verifies, and burns the code on any failure.
//  6. The displayer proves the same, so the joiner knows it reached the right
//     machine and not a relay.
//  7. Both pin the other's key.

// PairingWindow is how long a displayed code stays valid.
//
// Five minutes is long enough to walk to another room and short enough that a
// code left on a screen stops being a credential quickly.
// Fifteen minutes, raised from five.
//
// The window is not what protects a pairing: the secret is 128 bits, the tag
// stops an attacker ever collecting a grindable proof, only one attempt is
// accepted per code, and the listener takes one connection at a time. Tripling
// the clock changes none of that.
//
// What five minutes did do was punish the actual workflow. The code is forty
// characters, and it has to be carried to another machine, in another room,
// where a dashboard has to be opened and an address typed before the code is.
// Somebody who mistypes one character does not get a retry, because the attempt
// is spent, so they walk back for a fresh code with the clock already running.
// Fifteen minutes absorbs one such round trip; five did not.
const PairingWindow = 15 * time.Minute

// Pairing message types.
const (
	TypePairRequest  = "pair_request"
	TypePairResponse = "pair_response"
)

// PairRequest is the joiner's proof.
type PairRequest struct {
	PeerID string `json:"peer_id"`
	Label  string `json:"label,omitempty"`
	Proof  []byte `json:"proof"`
	// ListenPort is where the joiner accepts connections.
	//
	// Without it the displaying side records the joiner's *ephemeral source
	// port* as its address, which is what happened, and meant a freshly paired
	// pair could never connect if the displayer was the side that dials.
	ListenPort int `json:"listen_port,omitempty"`
}

// PairResponse is the displayer's counter-proof.
type PairResponse struct {
	PeerID string `json:"peer_id"`
	Label  string `json:"label,omitempty"`
	Proof  []byte `json:"proof"`
	// ListenPort is where the displaying side accepts connections. The joiner
	// already dialled it, so this is confirmation rather than news, but it keeps
	// the two directions symmetrical.
	ListenPort int `json:"listen_port,omitempty"`
}

// Errors a caller may want to tell apart when explaining a failure.
var (
	ErrNoPairingSession = errors.New("dispatch: no pairing session is open")
	ErrPairingExpired   = errors.New("dispatch: the pairing code has expired")
	ErrPairingUsed      = errors.New("dispatch: the pairing code has already been used")
	ErrWrongMachine     = errors.New("dispatch: that code belongs to a different machine")

	// ErrPeerDeclined is the far side answering the handshake and then saying
	// goodbye, which is what it does when no pairing window is open.
	//
	// **This is not a network failure and used to be reported as one.** The
	// connection succeeded, TLS completed, and the other machine replied; it
	// simply had nothing to pair with. Falling through to the generic case
	// printed "could not reach that address" over a connection that had plainly
	// been reached, and sent people to check addresses, firewalls and cables
	// that were all correct. The real cause is almost always a code that has
	// already been used, since codes are single use.
	ErrPeerDeclined = errors.New("dispatch: the other machine is not showing a pairing code")
	ErrBadProof     = errors.New("dispatch: the pairing code is wrong")
)

// PairingSession is one open invitation to pair.
//
// Single-use and short-lived, and **burned on the first bad proof** rather than
// after some number of attempts. There is no legitimate reason to get a pairing
// code wrong against the machine that just displayed it, so one failure is
// treated as an attempt rather than a typo. The user re-displays a code, which
// costs them a moment and costs an attacker the whole 128-bit search.
type PairingSession struct {
	mu       sync.Mutex
	code     JoinCode
	expires  time.Time
	consumed bool

	// result carries the paired peer to whoever is waiting on the UI side.
	result chan PairedPeer
}

// PairedPeer is what a completed pairing produced.
type PairedPeer struct {
	PeerID    string
	PublicKey ed25519.PublicKey
	Label     string
	Addr      string
}

// NewPairingSession mints a code for this identity.
func NewPairingSession(id *Identity, now time.Time) (*PairingSession, error) {
	code, err := NewJoinCode(id.Public())
	if err != nil {
		return nil, err
	}
	return &PairingSession{
		code:    code,
		expires: now.Add(PairingWindow),
		result:  make(chan PairedPeer, 1),
	}, nil
}

// Code is the string to show the operator.
func (ps *PairingSession) Code() string { return ps.code.String() }

// ExpiresAt is when the code stops working.
func (ps *PairingSession) ExpiresAt() time.Time { return ps.expires }

// Result waits for a pairing to complete, or for the context to end.
func (ps *PairingSession) Result(ctx context.Context) (PairedPeer, error) {
	select {
	case p := <-ps.result:
		return p, nil
	case <-ctx.Done():
		return PairedPeer{}, ctx.Err()
	}
}

// Cancel closes the window immediately, which is what closing the pairing screen
// must do. A code that outlives the screen showing it is a credential nobody is
// watching.
func (ps *PairingSession) Cancel() {
	ps.mu.Lock()
	ps.consumed = true
	ps.mu.Unlock()
}

// expired reports whether the window has closed, by time or by use.
func (ps *PairingSession) expired(now time.Time) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.consumed || now.After(ps.expires)
}

// claim takes the session for one attempt, or explains why it cannot.
func (ps *PairingSession) claim(now time.Time) (JoinCode, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.consumed {
		return JoinCode{}, ErrPairingUsed
	}
	if now.After(ps.expires) {
		return JoinCode{}, ErrPairingExpired
	}
	// Consumed on claim rather than on success: a failed attempt burns the code.
	ps.consumed = true
	return ps.code, nil
}

// AcceptPairing runs the displaying side of the exchange on an accepted
// connection whose handshake has completed.
func (id *Identity) AcceptPairing(conn *Conn, ps *PairingSession, label string, listenPort int, now time.Time) (PairedPeer, error) {
	if ps == nil {
		return PairedPeer{}, ErrNoPairingSession
	}
	code, err := ps.claim(now)
	if err != nil {
		return PairedPeer{}, err
	}

	binding, err := Binding(conn.tc)
	if err != nil {
		return PairedPeer{}, err
	}

	env, err := conn.Receive()
	if err != nil {
		return PairedPeer{}, err
	}
	if env.Type != TypePairRequest {
		return PairedPeer{}, fmt.Errorf("dispatch: expected %s, got %s", TypePairRequest, env.Type)
	}
	req, err := DecodeBody[PairRequest](env)
	if err != nil {
		return PairedPeer{}, err
	}

	joiner := conn.PublicKey()
	if !VerifyPairProof(code.Secret, binding, joiner, req.Proof) {
		return PairedPeer{}, ErrBadProof
	}

	// Prove ourselves in return, so the joiner knows it reached this machine and
	// not something relaying to it.
	if err := conn.Send(TypePairResponse, PairResponse{
		PeerID:     id.PeerID(),
		Label:      label,
		Proof:      PairProof(code.Secret, binding, id.Public()),
		ListenPort: listenPort,
	}); err != nil {
		return PairedPeer{}, err
	}

	peer := PairedPeer{
		PeerID:    PeerIDFor(joiner),
		PublicKey: joiner,
		Label:     req.Label,
		// The joiner's listening address, not the ephemeral port it dialled
		// from. Host from the connection we are holding, port from what it
		// claimed, see dialAddr.
		Addr: dialAddr(conn.RemoteAddr(), req.ListenPort),
	}
	select {
	case ps.result <- peer:
	default:
	}
	return peer, nil
}

// JoinWithCode runs the joining side: dial, verify, prove, verify the reply.
//
// The order matters and is the reason this is not simply "connect and send a
// password". Step 2 (checking the key tag before sending anything) is what
// stops an on-path attacker from ever receiving a proof they could attack
// offline.
func JoinWithCode(ctx context.Context, id *Identity, addr, codeText, label string, listenPort int) (PairedPeer, error) {
	code, err := ParseJoinCode(codeText)
	if err != nil {
		return PairedPeer{}, err
	}

	// The verifier runs inside the handshake, so a wrong machine is rejected
	// before any application byte is written to it.
	check := func(pub ed25519.PublicKey) error {
		if !code.Matches(pub) {
			return ErrWrongMachine
		}
		return nil
	}
	cfg, err := ClientTLS(id, check)
	if err != nil {
		return PairedPeer{}, err
	}

	d := net.Dialer{Timeout: HandshakeTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return PairedPeer{}, fmt.Errorf("dispatch: cannot reach %s: %w", addr, err)
	}
	conn, err := Handshake(ctx, raw, cfg, false)
	if err != nil {
		if errors.Is(err, ErrWrongMachine) {
			return PairedPeer{}, ErrWrongMachine
		}
		return PairedPeer{}, err
	}
	defer conn.Close()

	binding, err := Binding(conn.tc)
	if err != nil {
		return PairedPeer{}, err
	}
	if err := conn.Send(TypePairRequest, PairRequest{
		PeerID:     id.PeerID(),
		Label:      label,
		Proof:      PairProof(code.Secret, binding, id.Public()),
		ListenPort: listenPort,
	}); err != nil {
		return PairedPeer{}, err
	}

	env, err := conn.Receive()
	if err != nil {
		// The far side rejecting us looks like a closed connection, which is a
		// poor thing to show a person who mistyped a code.
		return PairedPeer{}, fmt.Errorf("%w: the other machine rejected it", ErrBadProof)
	}
	if env.Type != TypePairResponse {
		// Bye specifically means "I have no pairing window open", which is a
		// state the reader can act on, rather than a protocol violation.
		if env.Type == TypeBye {
			return PairedPeer{}, ErrPeerDeclined
		}
		return PairedPeer{}, fmt.Errorf("dispatch: expected %s, got %s", TypePairResponse, env.Type)
	}
	resp, err := DecodeBody[PairResponse](env)
	if err != nil {
		return PairedPeer{}, err
	}

	displayer := conn.PublicKey()
	if !VerifyPairProof(code.Secret, binding, displayer, resp.Proof) {
		// This is the on-path attacker case: something completed a TLS session
		// with us and could not prove it holds the secret.
		return PairedPeer{}, ErrBadProof
	}

	return PairedPeer{
		PeerID:    PeerIDFor(displayer),
		PublicKey: displayer,
		Label:     resp.Label,
		Addr:      addr,
	}, nil
}

// pairingVerifier admits any key while a pairing session is open, and only
// paired keys otherwise.
//
// One port rather than two: a second listener is a second thing to firewall and
// a second thing to forget to close. The window is narrow, a session is open
// only while somebody is looking at a pairing screen, and an admitted stranger
// still has to produce a proof before anything is written down.
func pairingVerifier(keys []ed25519.PublicKey, hasSession func() bool) KeyVerifier {
	pinned := PinnedToAny(keys)
	return func(pub ed25519.PublicKey) error {
		if hasSession() {
			return nil
		}
		return pinned(pub)
	}
}

// dialAddr builds an address to dial a peer at.
//
// **The host comes from the connection we are already holding; only the port
// comes from what the peer said.** A peer that could name a host could point us
// at a third party, a redirect primitive handed to the exact participant the
// merge rules assume may be compromised. It can choose its own port and nothing
// else. A port of zero yields an empty address, which the dial loop skips.
func dialAddr(remote net.Addr, port int) string {
	if port <= 0 || port > 65535 {
		return ""
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
