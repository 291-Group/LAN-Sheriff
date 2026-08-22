package dispatch

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// A live connection to one peer, with every limit from
// docs/DISPATCH-PROTOCOL.md §6 applied.
//
// Each limit exists for a named adversary. They are constants with comments
// rather than configuration, because a limit a user can raise is a limit an
// attacker can ask them to raise.

const (
	// HandshakeTimeout bounds how long a connection may take to authenticate.
	// Against a slow-loris that opens sockets and never finishes (A1).
	HandshakeTimeout = 10 * time.Second

	// IdleTimeout closes a connection that has said nothing. Longer than the
	// keep-alive interval so a healthy quiet peer is never dropped.
	IdleTimeout = 90 * time.Second

	// FrameDeadline bounds a single read or write once started. A peer that
	// sends half a frame and stops must not hold the reader forever.
	FrameDeadline = 30 * time.Second

	// KeepAlive is how often a ping goes out on an otherwise silent connection.
	KeepAlive = 30 * time.Second

	// MaxMessagesPerSecond is the sustained rate one peer may send at.
	MaxMessagesPerSecond = 20

	// MaxBurst is how many messages may arrive at once before the rate applies.
	// A peer legitimately sends several summaries back to back after
	// reconnecting, so a burst allowance avoids punishing normal behaviour.
	MaxBurst = 60
)

// ErrRateLimited is returned when a peer exceeds its message allowance.
var ErrRateLimited = errors.New("dispatch: peer exceeded its message rate")

// Conn is an authenticated connection to one peer.
//
// Safe for one reader and one writer concurrently, which is how it is used: a
// read loop and a write pump. It is *not* safe for two concurrent writers, so
// all sends go through Send, which holds a mutex.
type Conn struct {
	tc     *tls.Conn
	peerID string
	pub    ed25519.PublicKey

	writeMu sync.Mutex
	bucket  *rateBucket

	// pending is a message put back by Unread. Not guarded: it is written and
	// read on the single goroutine that owns a connection before any other
	// starts using it.
	pending *Envelope
}

// NewConn wraps a connection whose handshake has already completed.
func NewConn(tc *tls.Conn) (*Conn, error) {
	pub, err := PeerKeyOf(tc)
	if err != nil {
		return nil, err
	}
	return &Conn{
		tc:     tc,
		peerID: PeerIDFor(pub),
		pub:    pub,
		bucket: newRateBucket(MaxMessagesPerSecond, MaxBurst),
	}, nil
}

// Handshake completes the TLS handshake under HandshakeTimeout.
//
// Separate from NewConn so the timeout applies to the handshake specifically:
// this is the phase an unauthenticated stranger can reach, so it is the phase
// that must be bounded most tightly.
func Handshake(ctx context.Context, raw net.Conn, cfg *tls.Config, isServer bool) (*Conn, error) {
	var tc *tls.Conn
	if isServer {
		tc = tls.Server(raw, cfg)
	} else {
		tc = tls.Client(raw, cfg)
	}

	hctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		tc.Close()
		return nil, fmt.Errorf("dispatch: handshake: %w", err)
	}
	return NewConn(tc)
}

// PeerID is the identity that authenticated on this connection.
//
// Taken from the pinned key that completed the handshake, never from anything
// the peer said afterwards. Everything written to the store is attributed with
// this, which is what makes "a peer may only speak about itself" enforceable.
func (c *Conn) PeerID() string { return c.peerID }

// PublicKey returns the peer's authenticated key.
func (c *Conn) PublicKey() ed25519.PublicKey { return c.pub }

// RemoteAddr reports where the peer is, for reconnection hints only.
func (c *Conn) RemoteAddr() net.Addr { return c.tc.RemoteAddr() }

// Send writes one message.
func (c *Conn) Send(msgType string, body any) error {
	payload, err := EncodeMessage(msgType, body)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.tc.SetWriteDeadline(time.Now().Add(FrameDeadline)); err != nil {
		return err
	}
	return WriteFrame(c.tc, payload)
}

// Receive reads one message, applying the idle timeout and the rate limit.
//
// The rate limit is checked *after* a frame is read rather than before, because
// the cost being limited is the work a message causes, and a peer cannot be
// prevented from putting bytes on a socket. A peer over its allowance gets
// ErrRateLimited and the caller closes the connection.
func (c *Conn) Receive() (Envelope, error) {
	// A message put back by Unread is returned before anything is read from the
	// socket. See Unread for why the listener needs it.
	if c.pending != nil {
		env := *c.pending
		c.pending = nil
		return env, nil
	}
	if err := c.tc.SetReadDeadline(time.Now().Add(IdleTimeout)); err != nil {
		return Envelope{}, err
	}
	payload, err := ReadFrame(c.tc)
	if err != nil {
		return Envelope{}, err
	}
	if !c.bucket.allow(time.Now()) {
		return Envelope{}, ErrRateLimited
	}
	return DecodeEnvelope(payload)
}

// Unread puts one message back, so the next Receive returns it.
//
// # Why a listener needs this
//
// Pairing and ordinary peer traffic share a port, and the listener used to
// decide between them by whether it recognised the key: a known key was always
// treated as a peer reconnecting. That is wrong whenever a machine you have
// unpaired still has you paired, which is the normal state after one side
// unpairs, because unpairing is local. The other machine then dials in to pair,
// is recognised, is handed to the session loop, and gets a goodbye.
//
// The client already says which it wants in its first message: `hello` for a
// session, `pair_request` for pairing. So the listener reads that message and
// then puts it back for whichever handler it chose, rather than guessing from
// the key and being unable to change its mind.
func (c *Conn) Unread(env Envelope) {
	c.pending = &env
}

// Close ends the connection. Safe to call more than once, and on a zero value.
//
// The nil check is not defensive clutter: Close is the one method callers invoke
// from a defer without checking anything first, and one that panics turns an
// ordinary teardown into a crash. Nothing in the running system can produce a
// Conn without a transport (NewConn and Handshake both set one) but a Close
// that only works on well-formed values is a poor primitive.
func (c *Conn) Close() error {
	if c == nil || c.tc == nil {
		return nil
	}
	return c.tc.Close()
}

// SayGoodbye sends a bye and closes, best effort.
//
// Advisory: a peer may vanish without one and the code treats both identically,
// so a failure here is not worth reporting.
func (c *Conn) SayGoodbye(reason string) {
	_ = c.Send(TypeBye, Bye{Reason: reason})
	_ = c.Close()
}

// rateBucket is a token bucket.
//
// Hand-written rather than pulled in: it is fifteen lines, and
// golang.org/x/time/rate would be a dependency added for one of them. That is
// the test D13 sets, this is not something a reviewer would be uncomfortable
// seeing written out.
type rateBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	perSec   float64
	lastFill time.Time
}

func newRateBucket(perSec, burst int) *rateBucket {
	return &rateBucket{
		tokens: float64(burst), max: float64(burst),
		perSec: float64(perSec), lastFill: time.Now(),
	}
}

func (b *rateBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.perSec
		if b.tokens > b.max {
			b.tokens = b.max
		}
		b.lastFill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
