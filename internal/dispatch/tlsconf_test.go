package dispatch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func testIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// serverResult is what the accepting side observed.
type serverResult struct {
	handshakeErr error
	payload      []byte
	readErr      error
	binding      []byte
	peer         ed25519.PublicKey
}

// runServer accepts exactly one connection, completes the handshake, and tries
// to read one frame. Returns everything it saw so a test can assert on the
// order in which things failed.
func runServer(t *testing.T, id *Identity, check KeyVerifier) (addr string, result <-chan serverResult, cleanup func()) {
	t.Helper()
	cfg, err := ServerTLS(id, check)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan serverResult, 1)
	var once sync.Once
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- serverResult{handshakeErr: err}
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))

		var res serverResult
		if err := tc.Handshake(); err != nil {
			res.handshakeErr = err
			out <- res
			return
		}
		res.binding, _ = Binding(tc)
		res.peer, _ = PeerKeyOf(tc)
		res.payload, res.readErr = ReadFrame(tc)
		out <- res
	}()

	return ln.Addr().String(), out, func() { once.Do(func() { ln.Close() }) }
}

// The ordinary case: two paired instances exchange a frame.
func TestPairedPeersExchangeAFrame(t *testing.T) {
	server, client := testIdentity(t), testIdentity(t)

	addr, results, cleanup := runServer(t, server, PinnedTo(client.Public()))
	defer cleanup()

	cfg, err := ClientTLS(client, PinnedTo(server.Public()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("a paired peer failed to connect: %v", err)
	}
	defer conn.Close()

	want := []byte(`{"v":1,"type":"ping"}`)
	if err := WriteFrame(conn, want); err != nil {
		t.Fatal(err)
	}

	res := <-results
	if res.handshakeErr != nil {
		t.Fatalf("handshake failed between paired peers: %v", res.handshakeErr)
	}
	if res.readErr != nil {
		t.Fatalf("reading the frame: %v", res.readErr)
	}
	if !bytes.Equal(res.payload, want) {
		t.Errorf("payload = %q, want %q", res.payload, want)
	}
	if !res.peer.Equal(client.Public()) {
		t.Error("the server did not recover the client's identity key")
	}
}

// The property the design turns on: a stranger is dropped during the handshake,
// so the frame decoder never sees anything they sent.
func TestUnpairedPeerIsDroppedBeforeAnyPayloadIsRead(t *testing.T) {
	server, stranger := testIdentity(t), testIdentity(t)
	paired := testIdentity(t)

	// The server pins somebody else entirely.
	addr, results, cleanup := runServer(t, server, PinnedTo(paired.Public()))
	defer cleanup()

	cfg, err := ClientTLS(stranger, PinnedTo(server.Public()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err == nil {
		// TLS 1.3 clients can finish before the server rejects the client
		// certificate, so a successful dial is allowed here. Writing must still
		// never reach the decoder.
		_ = WriteFrame(conn, []byte(`{"v":1,"type":"summary"}`))
		conn.Close()
	}

	res := <-results
	if res.handshakeErr == nil {
		t.Fatal("the server completed a handshake with an unpaired peer")
	}
	if !errors.Is(res.handshakeErr, ErrUnpinnedPeer) {
		t.Errorf("handshake error = %v, want it to wrap ErrUnpinnedPeer", res.handshakeErr)
	}
	if res.payload != nil {
		t.Fatalf("the decoder read %q from an unpaired peer", res.payload)
	}
}

// The other direction: a client must refuse a server that is not the machine it
// paired with, which is what stops a impostor at the pinned address.
func TestClientRefusesAnUnpinnedServer(t *testing.T) {
	server, client := testIdentity(t), testIdentity(t)
	somebodyElse := testIdentity(t)

	addr, _, cleanup := runServer(t, server, PinnedTo(client.Public()))
	defer cleanup()

	cfg, err := ClientTLS(client, PinnedTo(somebodyElse.Public()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err == nil {
		conn.Close()
		t.Fatal("the client accepted a server it had not pinned")
	}
	if !errors.Is(err, ErrUnpinnedPeer) {
		t.Errorf("error = %v, want it to wrap ErrUnpinnedPeer", err)
	}
}

// A peer listener admits any of several paired keys.
func TestPinnedToAny(t *testing.T) {
	a, b, outsider := testIdentity(t), testIdentity(t), testIdentity(t)
	check := PinnedToAny([]ed25519.PublicKey{a.Public(), b.Public()})

	if err := check(a.Public()); err != nil {
		t.Errorf("first paired key rejected: %v", err)
	}
	if err := check(b.Public()); err != nil {
		t.Errorf("second paired key rejected: %v", err)
	}
	if err := check(outsider.Public()); !errors.Is(err, ErrUnpinnedPeer) {
		t.Errorf("outsider error = %v, want ErrUnpinnedPeer", err)
	}
	if err := PinnedToAny(nil)(a.Public()); !errors.Is(err, ErrUnpinnedPeer) {
		t.Errorf("an empty peer set admitted a key: %v", err)
	}
}

// Both ends must derive the same binding, and two sessions must differ. This is
// the property the pairing proof depends on, asserted against the real
// configuration rather than the spike's.
func TestBindingAgreesAndIsPerSession(t *testing.T) {
	server, client := testIdentity(t), testIdentity(t)

	dial := func() ([]byte, []byte) {
		t.Helper()
		addr, results, cleanup := runServer(t, server, PinnedTo(client.Public()))
		defer cleanup()

		cfg, err := ClientTLS(client, PinnedTo(server.Public()))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		cb, err := Binding(conn)
		if err != nil {
			t.Fatal(err)
		}
		_ = WriteFrame(conn, []byte("x"))
		res := <-results
		return res.binding, cb
	}

	s1, c1 := dial()
	if !bytes.Equal(s1, c1) {
		t.Fatal("the two ends derived different bindings for one session")
	}
	s2, _ := dial()
	if bytes.Equal(s1, s2) {
		t.Fatal("two sessions produced the same binding, so channel binding is useless")
	}
}

// Binding must not be available before the handshake, or a caller could compare
// two zero values and believe they matched.
func TestBindingRefusedBeforeHandshake(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	cfg, err := ClientTLS(testIdentity(t), AcceptAnyKey())
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(c, cfg)
	if _, err := Binding(conn); err == nil {
		t.Error("Binding returned a value before the handshake completed")
	}
	if _, err := PeerKeyOf(conn); err == nil {
		t.Error("PeerKeyOf returned a key before the handshake completed")
	}
}

// The negotiated version is pinned: the pairing exporter and the absence of
// downgrade handling both assume 1.3.
func TestNegotiatesTLS13Only(t *testing.T) {
	server, client := testIdentity(t), testIdentity(t)

	addr, results, cleanup := runServer(t, server, PinnedTo(client.Public()))
	defer cleanup()

	cfg, err := ClientTLS(client, PinnedTo(server.Public()))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("negotiated version 0x%04x, want TLS 1.3 (0x%04x)", v, tls.VersionTLS13)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Error("the configuration permits a version other than 1.3")
	}
	if !cfg.SessionTicketsDisabled {
		t.Error("session tickets are enabled; 0-RTT data is replayable")
	}
	_ = WriteFrame(conn, []byte("x"))
	<-results
}

// A client offering no certificate at all must not get through: an anonymous
// peer has nothing to say in this protocol.
func TestAnonymousClientRejected(t *testing.T) {
	server := testIdentity(t)
	addr, results, cleanup := runServer(t, server, AcceptAnyKey())
	defer cleanup()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // the test is about the server's demand, not ours
	})
	if err == nil {
		_ = WriteFrame(conn, []byte(`{"v":1}`))
		conn.Close()
	}

	res := <-results
	if res.handshakeErr == nil {
		t.Fatal("the server accepted a client presenting no certificate")
	}
	if res.payload != nil {
		t.Errorf("read %q from an unauthenticated client", res.payload)
	}
}
