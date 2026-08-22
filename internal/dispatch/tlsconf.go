package dispatch

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// TLS configuration for the Dispatch. See docs/DISPATCH-PROTOCOL.md §4 (D-3)
// and §6.
//
// The shape here looks alarming at a glance and is deliberate: InsecureSkipVerify
// is true and VerifyPeerCertificate does the work instead. That is not a
// weakening of verification, it is a *replacement* of it. There is no CA, no
// chain to build, no name to validate and no revocation to consult, a peer's
// identity is a public key the operator pinned by hand during pairing, and the
// only correct check is whether the presented key is that exact key.
//
// Leaving Go's default verification enabled would achieve nothing here except
// requiring a CA that would then have to be trusted for something.

// ErrUnpinnedPeer is returned by a verifier for a key that is not paired. It
// surfaces during the handshake, which is the point: the connection dies before
// a single application byte is read from it.
var ErrUnpinnedPeer = errors.New("dispatch: peer key is not paired")

// KeyVerifier decides whether a presented public key may proceed.
//
// A function rather than a peer list, because the two listeners need different
// answers from the same machinery: the peer listener admits only pinned keys,
// while the pairing listener admits an unknown key precisely once and relies on
// the join code to establish who it belongs to.
type KeyVerifier func(ed25519.PublicKey) error

// PinnedTo returns a verifier accepting exactly one key.
func PinnedTo(want ed25519.PublicKey) KeyVerifier {
	return func(got ed25519.PublicKey) error {
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fmt.Errorf("%w: expected %s, got %s",
				ErrUnpinnedPeer, PeerIDFor(want), PeerIDFor(got))
		}
		return nil
	}
}

// PinnedToAny returns a verifier accepting any key in the set. Used by the peer
// listener, which does not know which paired peer is dialling until it arrives.
func PinnedToAny(keys []ed25519.PublicKey) KeyVerifier {
	return func(got ed25519.PublicKey) error {
		// Every candidate is compared even after a match, so the time taken does
		// not reveal the position of a key in the set.
		found := 0
		for _, k := range keys {
			found |= subtle.ConstantTimeCompare(got, k)
		}
		if found != 1 {
			return fmt.Errorf("%w: %s", ErrUnpinnedPeer, PeerIDFor(got))
		}
		return nil
	}
}

// AcceptAnyKey admits any well-formed key. **Only for the pairing listener**,
// where the join code rather than the key establishes trust, and only while a
// pairing session is open.
func AcceptAnyKey() KeyVerifier {
	return func(ed25519.PublicKey) error { return nil }
}

// verifier adapts a KeyVerifier to the callback crypto/tls expects.
func verifier(check KeyVerifier) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("dispatch: peer presented no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("dispatch: parsing peer certificate: %w", err)
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("dispatch: peer key is %T, want ed25519", cert.PublicKey)
		}
		return check(pub)
	}
}

// baseConfig is the configuration both ends share.
func baseConfig(id *Identity, check KeyVerifier) (*tls.Config, error) {
	der, err := id.Certificate()
	if err != nil {
		return nil, fmt.Errorf("dispatch: building certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  id.priv,
		}},
		// TLS 1.3 exactly. Not a floor with a higher ceiling: pinning both ends
		// removes downgrade negotiation as a concern entirely, and 1.3 is the
		// only version whose exporter this protocol's pairing depends on.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// Session resumption and 0-RTT are off. 0-RTT data is replayable by
		// construction, and on a LAN with long-lived connections resumption
		// saves nothing worth that.
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
		// Replaced by the pin below, not weakened. See the package comment.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifier(check),
	}, nil
}

// ServerTLS builds the listener's configuration.
func ServerTLS(id *Identity, check KeyVerifier) (*tls.Config, error) {
	cfg, err := baseConfig(id, check)
	if err != nil {
		return nil, err
	}
	// A client that presents no certificate is rejected by the handshake itself,
	// before the verifier is consulted. Mutual authentication is not optional in
	// this protocol: an anonymous peer has nothing to say.
	cfg.ClientAuth = tls.RequireAnyClientCert
	return cfg, nil
}

// ClientTLS builds the dialler's configuration.
func ClientTLS(id *Identity, check KeyVerifier) (*tls.Config, error) {
	cfg, err := baseConfig(id, check)
	if err != nil {
		return nil, err
	}
	// ServerName is never sent: there is no name to validate, and a name would
	// leak which peer is being dialled to anyone watching the handshake.
	cfg.ServerName = ""
	return cfg, nil
}

// Binding derives the channel-binding value for a completed connection.
//
// This is what makes a pairing proof worthless outside the session it was made
// in, see docs/DISPATCH-PROTOCOL.md §5. It must be called only after the
// handshake completes; on an incomplete connection it returns an error rather
// than a zero value that would compare equal on both sides of an attack.
func Binding(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("dispatch: channel binding requested before the handshake completed")
	}
	b, err := state.ExportKeyingMaterial(ExporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("dispatch: exporting channel binding: %w", err)
	}
	return b, nil
}

// PeerKeyOf returns the public key the peer authenticated with.
func PeerKeyOf(conn *tls.Conn) (ed25519.PublicKey, error) {
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("dispatch: peer key requested before the handshake completed")
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("dispatch: peer presented no certificate")
	}
	pub, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("dispatch: peer key is %T, want ed25519",
			state.PeerCertificates[0].PublicKey)
	}
	return pub, nil
}
