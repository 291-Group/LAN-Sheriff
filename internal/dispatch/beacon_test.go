package dispatch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func testPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestBeaconRoundTrip(t *testing.T) {
	pub := testPub(t)
	tag, port, ok := decodeBeacon(encodeBeacon(pub, 2912))
	if !ok {
		t.Fatal("a beacon we encoded did not decode")
	}
	if port != 2912 {
		t.Errorf("port = %d, want 2912", port)
	}
	if tag != beaconTag(pub) {
		t.Error("the tag did not survive the round trip")
	}
}

// The tag identifies a peer to somebody who already holds its key, and to
// nobody else. It must not be the peer id itself: that string appears in the
// UI, in logs and in the API, and publishing it on the wire would hand out a
// correlatable identifier to anyone listening.
func TestBeaconTagIsNotThePeerID(t *testing.T) {
	pub := testPub(t)
	tag := beaconTag(pub)
	id := PeerIDFor(pub)

	if bytes.Contains([]byte(id), tag[:]) {
		t.Error("the beacon tag appears inside the peer id")
	}
	// Derivable by anyone holding the key, which is what makes matching work.
	if beaconTag(pub) != tag {
		t.Error("the tag is not deterministic")
	}
	if beaconTag(testPub(t)) == tag {
		t.Error("two keys produced the same tag")
	}
}

// Anything that is not one of ours must be rejected before it is interpreted,
// this listens on a shared multicast group.
func TestBeaconRejectsForeignTraffic(t *testing.T) {
	good := encodeBeacon(testPub(t), 2912)

	cases := map[string][]byte{
		"empty":           {},
		"too short":       good[:10],
		"too long":        append(append([]byte{}, good...), 0),
		"wrong magic":     append([]byte{0, 0, 0, 0}, good[4:]...),
		"unknown version": append(append([]byte{}, good[:4]...), append([]byte{99}, good[5:]...)...),
		"random":          []byte("an SSDP NOTIFY or somebody's printer"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := decodeBeacon(data); ok {
				t.Errorf("accepted %s", name)
			}
		})
	}
}

// A port of zero cannot be dialled, so a beacon carrying one is useless and is
// refused rather than stored as an address nothing can reach.
func TestBeaconRejectsZeroPort(t *testing.T) {
	if _, _, ok := decodeBeacon(encodeBeacon(testPub(t), 0)); ok {
		t.Error("a beacon advertising port 0 was accepted")
	}
}

// The beacon must not carry anything that identifies the machine beyond the
// tag: no name, no address, no version. Fifteen bytes exactly.
func TestBeaconCarriesNothingElse(t *testing.T) {
	pub := testPub(t)
	b := encodeBeacon(pub, 2912)
	if len(b) != beaconLen {
		t.Fatalf("beacon is %d bytes, want %d", len(b), beaconLen)
	}
	// The peer id must not be recoverable from the datagram.
	if bytes.Contains(b, []byte(PeerIDFor(pub)[:8])) {
		t.Error("the datagram contains part of the peer id")
	}
	// Nor the raw public key.
	if bytes.Contains(b, pub[:8]) {
		t.Error("the datagram contains part of the public key")
	}
}

// A beacon may only move an address that has demonstrably stopped working.
//
// The first version relocated any peer that was not *currently* connected,
// which let a beacon overwrite a perfectly good address moments before it was
// used, it replaced a working loopback address with a LAN one and broke three
// tests. These are the four states that distinction turns on.
func TestOnlyRelocatesAnAddressThatHasFailed(t *testing.T) {
	svc := newService(t, newMemStore())
	svc.startedAt = time.Now()

	t.Run("a connected peer is never relocated", func(t *testing.T) {
		svc.mu.Lock()
		svc.live["LIVE"] = &Conn{}
		svc.mu.Unlock()
		defer func() { svc.mu.Lock(); delete(svc.live, "LIVE"); svc.mu.Unlock() }()

		if svc.unreachableLongEnough("LIVE") {
			t.Error("a connected peer was eligible for relocation")
		}
	})

	t.Run("a peer heard from recently is not relocated", func(t *testing.T) {
		svc.mu.Lock()
		svc.seen["RECENT"] = time.Now()
		svc.mu.Unlock()

		if svc.unreachableLongEnough("RECENT") {
			t.Error("a peer heard from just now was eligible for relocation")
		}
	})

	t.Run("a peer silent for long enough is relocated", func(t *testing.T) {
		svc.mu.Lock()
		svc.seen["SILENT"] = time.Now().Add(-2 * relocateAfter)
		svc.mu.Unlock()

		if !svc.unreachableLongEnough("SILENT") {
			t.Errorf("a peer silent for %v was not eligible", 2*relocateAfter)
		}
	})

	t.Run("a never-seen peer waits for the stored address to fail first", func(t *testing.T) {
		// Freshly started: the stored address has not had its chance yet.
		svc.startedAt = time.Now()
		if svc.unreachableLongEnough("NEVER") {
			t.Error("relocated before the stored address had been tried")
		}
		// Running long enough that it plainly is not working.
		svc.startedAt = time.Now().Add(-2 * relocateAfter)
		if !svc.unreachableLongEnough("NEVER") {
			t.Error("never relocated a peer that has never connected")
		}
	})
}
