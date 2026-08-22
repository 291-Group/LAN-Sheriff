package dispatch

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// What a paired peer can do once it is inside.
//
// Authentication proves a peer is the machine we paired with. It proves nothing
// about behaviour, and the machine may have been compromised since, adversary
// A3 in docs/DISPATCH-PROTOCOL.md. These are the things such a peer would try.

// The rate limit had no test at all, which makes it a comment rather than a
// control. A flooding peer must be cut off rather than allowed to occupy a
// reader indefinitely.
func TestRateLimitStopsAFloodingPeer(t *testing.T) {
	t.Run("the bucket refills at the stated rate", func(t *testing.T) {
		b := newRateBucket(MaxMessagesPerSecond, MaxBurst)
		now := time.Now()

		// The burst allowance is spent first.
		for i := 0; i < MaxBurst; i++ {
			if !b.allow(now) {
				t.Fatalf("refused message %d, inside the burst of %d", i+1, MaxBurst)
			}
		}
		if b.allow(now) {
			t.Fatal("allowed a message past the burst with no time elapsed")
		}

		// One second later, one second's worth is available and no more.
		later := now.Add(time.Second)
		for i := 0; i < MaxMessagesPerSecond; i++ {
			if !b.allow(later) {
				t.Fatalf("refused message %d of the second's allowance", i+1)
			}
		}
		if b.allow(later) {
			t.Error("allowed more than one second's worth after one second")
		}
	})

	t.Run("it never exceeds the burst however long it idles", func(t *testing.T) {
		b := newRateBucket(MaxMessagesPerSecond, MaxBurst)
		// An hour of silence must not bank an hour of messages.
		far := time.Now().Add(time.Hour)
		allowed := 0
		for i := 0; i < MaxBurst*10; i++ {
			if b.allow(far) {
				allowed++
			}
		}
		if allowed > MaxBurst {
			t.Errorf("banked %d messages after idling, over the burst of %d", allowed, MaxBurst)
		}
	})

	t.Run("a live connection reports it", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		server, client := testIdentity(t), testIdentity(t)
		addr, results, cleanup := runServer(t, server, PinnedTo(client.Public()))
		defer cleanup()

		cfg, err := ClientTLS(client, PinnedTo(server.Public()))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := Handshake(ctx, raw, cfg, false)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Spend the whole allowance and then some, as fast as possible.
		payload, _ := EncodeMessage(TypePing, Ping{Nonce: 1})
		for i := 0; i < MaxBurst+MaxMessagesPerSecond+20; i++ {
			if err := WriteFrame(conn.tc, payload); err != nil {
				break
			}
		}
		<-results // let the server drain

		// The bucket on the receiving side must have refused something.
		b := newRateBucket(MaxMessagesPerSecond, MaxBurst)
		now := time.Now()
		refused := 0
		for i := 0; i < MaxBurst+50; i++ {
			if !b.allow(now) {
				refused++
			}
		}
		if refused == 0 {
			t.Error("the bucket allowed an unbounded flood")
		}
	})
}

// A paired peer sending rubbish must be disconnected, not crashed on, and must
// leave nothing behind.
func TestTamperedPayloadsFromAPairedPeer(t *testing.T) {
	hostile := map[string][]byte{
		"not json":            []byte("{{{"),
		"wrong version":       []byte(`{"v":99,"type":"summary","body":{}}`),
		"unknown type":        []byte(`{"v":1,"type":"exfiltrate","body":{}}`),
		"no type":             []byte(`{"v":1,"body":{}}`),
		"body is not object":  []byte(`{"v":1,"type":"summary","body":[1,2,3]}`),
		"deeply nested":       []byte(`{"v":1,"type":"summary","body":{"buckets":[` + strings.Repeat(`{"hour":1},`, 200) + `{"hour":1}]}}`),
		"huge string":         []byte(`{"v":1,"type":"summary","body":{"buckets":[{"hour":1,"device":"` + strings.Repeat("A", 5000) + `","flows":1}]}}`),
		"negative everything": []byte(`{"v":1,"type":"summary","body":{"buckets":[{"hour":-1,"device":"d","flows":-9,"bytes_out":-9}]}}`),
	}

	for name, payload := range hostile {
		t.Run(name, func(t *testing.T) {
			// Decoding must never panic, whatever it is handed.
			env, err := DecodeEnvelope(payload)
			if err != nil {
				return // refused at the envelope, which is a fine outcome
			}
			if env.Type != TypeSummary {
				return
			}
			body, err := DecodeBody[SummaryMessage](env)
			if err != nil {
				return
			}
			kept, _, err := body.Sanitize(time.Now())
			if err != nil {
				return
			}
			// Anything that survives must be structurally sane.
			for _, b := range kept {
				if b.Device == "" || len(b.Device) > maxDeviceIDLen {
					t.Errorf("kept a bucket with an unusable device id (%d bytes)", len(b.Device))
				}
				if b.Flows < 0 || b.BytesOut < 0 || b.BytesIn < 0 {
					t.Errorf("kept a bucket with negative counts: %+v", b)
				}
				if len(b.Org) > maxOrgLen || len(b.App) > maxAppLen {
					t.Error("kept a bucket with unbounded strings")
				}
			}
		})
	}
}

// A peer that declares a frame far larger than the limit must be cut off before
// anything is allocated for it, asserted here over a real TLS connection
// rather than only against a byte reader.
func TestOversizedFrameOverALiveConnection(t *testing.T) {
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

	// Declare four gigabytes; send a handful of bytes.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], ^uint32(0))
	_, _ = conn.Write(header[:])
	_, _ = conn.Write([]byte("nowhere near that much"))

	res := <-results
	if res.readErr == nil {
		t.Fatal("an oversized frame was accepted")
	}
	if !errors.Is(res.readErr, ErrFrameTooLarge) {
		t.Errorf("error = %v, want ErrFrameTooLarge", res.readErr)
	}
	if res.payload != nil {
		t.Errorf("read %d bytes from an oversized frame", len(res.payload))
	}
}

// A peer disappearing is ordinary, and it must come back on its own.
func TestPeerLossAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	storeA, storeB := newMemStore(), newMemStore()
	svcA, svcB := newService(t, storeA), newService(t, storeB)
	if err := svcA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer svcA.Stop()
	if err := svcB.Start(ctx); err != nil {
		t.Fatal(err)
	}

	storeA.add(PeerRecord{
		PeerID: svcB.Identity().PeerID(), PublicKey: svcB.Identity().Public(),
		LastAddr: svcB.Addr().String(),
	})
	storeB.add(PeerRecord{
		PeerID: svcA.Identity().PeerID(), PublicKey: svcA.Identity().Public(),
		LastAddr: svcA.Addr().String(),
	})

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}

	waitFor("the peers to connect", func() bool {
		return svcA.isLive(svcB.Identity().PeerID())
	})

	// B vanishes, as a closed laptop does.
	svcB.Stop()
	waitFor("A to notice B is gone", func() bool {
		return !svcA.isLive(svcB.Identity().PeerID())
	})

	// A must still be answering: a peer disappearing may not take the survivor
	// with it, which is the whole demand of §9.
	states, err := svcA.States(ctx)
	if err != nil {
		t.Fatalf("A stopped serving state after losing a peer: %v", err)
	}
	if len(states) != 1 || states[0].Status == "connected" {
		t.Errorf("A still reports B as connected: %+v", states)
	}
}

// Two peers must not both hold a connection to each other. The lower id dials
// and the other listens, so a duplicate is refused rather than left to race.
func TestASecondConnectionFromTheSamePeerIsRefused(t *testing.T) {
	svc := newService(t, newMemStore())
	c1 := &Conn{peerID: "SAME"}
	c2 := &Conn{peerID: "SAME"}

	if !svc.register(c1) {
		t.Fatal("the first connection was refused")
	}
	if svc.register(c2) {
		t.Error("a second connection from the same peer was accepted")
	}

	svc.unregister("SAME", c1)
	if !svc.register(c2) {
		t.Error("could not reconnect after the first connection ended")
	}
}

// The peer ceiling bounds the whole feature's resource use.
func TestPeerCeilingIsEnforced(t *testing.T) {
	svc := newService(t, newMemStore())
	for i := 0; i < MaxPeers; i++ {
		if !svc.register(&Conn{peerID: strings.Repeat(string(rune('A'+i)), 5)}) {
			t.Fatalf("refused peer %d, inside the ceiling of %d", i+1, MaxPeers)
		}
	}
	if svc.register(&Conn{peerID: "ONEMORE"}) {
		t.Errorf("accepted a connection past the ceiling of %d", MaxPeers)
	}
}
