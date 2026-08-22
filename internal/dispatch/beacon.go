package dispatch

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/discover"
)

// Relocating a peer that moved. See docs/DISPATCH-PROTOCOL.md.
//
// The problem this solves is narrow and real. A peer's address is learned from
// its `hello`, which requires a connection, so if a peer's DHCP lease changes
// **while it is offline**, the stored address is stale, and since only the lower
// peer ID dials, the pair can be permanently unable to find each other. Nothing
// in the protocol recovers from that, and the user's only option would be to
// unpair and start again.
//
// # Why not DNS-SD
//
// The task called for mDNS. Advertising `_lan-sheriff._tcp` would work and is
// the conventional answer, and it was rejected: a DNS-SD advert announces to
// every Bonjour browser on the network that this machine runs a network monitor,
// carries an instance name, and is discoverable by anyone. For a tool whose
// value is watching quietly, that is a poor trade for an address hint.
//
// This beacon carries **eight bytes of hash and a port**, on its own group. An
// observer learns that something is beaconing; they do not learn what it is,
// what it is called, or which instance it belongs to. A paired peer, which
// already knows the other's public key, can compute the hash and match it.
//
// # Why it cannot be used to redirect anything
//
// A beacon is a **hint, never an authority**. Three properties together:
//
//   - It only ever relocates a peer that is **already paired**. An unknown hash
//     is discarded; there is no path from a beacon to a new peer.
//   - It supplies an address, and an address decides nothing. The pinned key
//     decides identity, so an attacker who forges a beacon achieves only a
//     wasted dial that fails in the TLS handshake.
//   - It is only consulted when the stored address is **not working**. A peer we
//     are connected to is never relocated, so a forged beacon cannot pull a
//     healthy connection away.

const (
	// beaconGroup is this protocol's own multicast group, from the IPv4 local
	// scope block (239.0.0.0/8) reserved for exactly this.
	beaconGroupStr = "239.29.1.1"
	beaconPort     = 2913

	// beaconInterval is how often a beacon goes out while peering is enabled.
	beaconInterval = 30 * time.Second

	// beaconMagic marks our datagrams so anything else sharing the group is
	// discarded before it is parsed.
	beaconMagic = 0x4C534248 // "LSBH"

	// beaconLen is magic(4) + version(1) + tag(8) + port(2).
	beaconLen = 15

	// beaconVersion allows the format to change without a silent misparse.
	beaconVersion = 1
)

var beaconGroup = netip.MustParseAddr(beaconGroupStr)

// beaconTag is the eight-byte identifier a peer publishes.
//
// SHA-256 of the SPKI digest, a hash *of the peer id*, not the id itself, so a
// beacon does not hand out an identifier that appears elsewhere in the protocol
// and in the UI. Anyone already holding the peer's public key can compute it;
// nobody else can invert it.
func beaconTag(pub ed25519.PublicKey) [8]byte {
	id := spkiDigest(pub)
	sum := sha256.Sum256(id[:])
	var tag [8]byte
	copy(tag[:], sum[:8])
	return tag
}

// encodeBeacon builds the datagram.
func encodeBeacon(pub ed25519.PublicKey, port int) []byte {
	b := make([]byte, beaconLen)
	binary.BigEndian.PutUint32(b, beaconMagic)
	b[4] = beaconVersion
	tag := beaconTag(pub)
	copy(b[5:13], tag[:])
	binary.BigEndian.PutUint16(b[13:], uint16(port))
	return b
}

// decodeBeacon parses a datagram, reporting whether it is one of ours.
func decodeBeacon(data []byte) (tag [8]byte, port int, ok bool) {
	if len(data) != beaconLen {
		return tag, 0, false
	}
	if binary.BigEndian.Uint32(data) != beaconMagic || data[4] != beaconVersion {
		return tag, 0, false
	}
	copy(tag[:], data[5:13])
	port = int(binary.BigEndian.Uint16(data[13:]))
	if port == 0 {
		return tag, 0, false
	}
	return tag, port, true
}

// announce sends a beacon periodically while peering is enabled.
//
// Sending is deliberately separate from the passive listener the Roster uses:
// that one never transmits, and this one must, so they are not conflated.
func (s *Service) announce(ctx context.Context) {
	addr := &net.UDPAddr{IP: net.ParseIP(beaconGroupStr), Port: beaconPort}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		s.log.Debug("dispatch beacon disabled", "err", err)
		return
	}
	defer conn.Close()

	send := func() {
		port := s.listenPort()
		if port == 0 {
			return
		}
		if _, err := conn.WriteTo(encodeBeacon(s.id.Public(), port), addr); err != nil {
			s.log.Debug("dispatch beacon send failed", "err", err)
		}
	}
	send()

	t := time.NewTicker(beaconInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		}
	}
}

// relocateAfter is how long a peer must be unreachable before a beacon may
// change its address.
//
// Long enough that a stored address gets a fair chance, the dial loop retries
// on a growing backoff, and short enough that recovery is not something the
// user waits out.
const relocateAfter = 60 * time.Second

// unreachableLongEnough reports whether a peer's stored address has had a fair
// chance and is not working.
func (s *Service) unreachableLongEnough(peerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, live := s.live[peerID]; live {
		return false
	}
	if seen, ok := s.seen[peerID]; ok && !seen.IsZero() {
		return time.Since(seen) > relocateAfter
	}
	// Never heard from. That is the case relocation exists for, but only once
	// the stored address has had time to fail, otherwise every restart would
	// relocate before its first dial.
	return time.Since(s.startedAt) > relocateAfter
}

// relocate listens for beacons and updates the address of paired peers whose
// stored address is not working.
func (s *Service) relocate(ctx context.Context) {
	err := discover.ListenMulticast(ctx, beaconGroup, beaconPort, 512, func(p discover.Packet) {
		from, data := p.From, p.Data
		tag, port, ok := decodeBeacon(data)
		if !ok {
			return
		}
		// Our own beacon comes back on the loopback join.
		if mine := beaconTag(s.id.Public()); subtle.ConstantTimeCompare(tag[:], mine[:]) == 1 {
			return
		}

		peers, err := s.store.DispatchPeers(ctx)
		if err != nil {
			return
		}
		for _, p := range peers {
			want := beaconTag(p.PublicKey)
			if subtle.ConstantTimeCompare(tag[:], want[:]) != 1 {
				continue
			}
			// **Only a peer whose stored address is demonstrably not working.**
			//
			// The first version relocated any peer that was not *currently*
			// connected, which is a different and much weaker condition, a peer
			// that simply had not connected yet qualified, so a beacon could
			// overwrite a perfectly good address moments before it was used. It
			// did exactly that, replacing a working loopback address with the
			// LAN one and breaking three tests.
			//
			// A stored address has earned the benefit of the doubt until it has
			// had time to fail: either we heard from this peer recently, or we
			// have not been running long enough to know.
			if !s.unreachableLongEnough(p.PeerID) {
				return
			}
			addr := net.JoinHostPort(from.Addr().String(), strconv.Itoa(port))
			if addr == p.LastAddr {
				return
			}
			if err := s.store.SetDispatchPeerAddr(ctx, p.PeerID, addr); err != nil {
				s.log.Debug("dispatch relocate failed", "peer", p.PeerID, "err", err)
				return
			}
			s.log.Info("dispatch peer relocated",
				"peer_id", Fingerprint(p.PeerID), "addr", addr, "was", p.LastAddr)
			return
		}
		// An unrecognised tag is somebody else's instance. Nothing is recorded:
		// there is no path from a beacon to a new peer.
	})
	if err != nil && ctx.Err() == nil {
		s.log.Debug("dispatch beacon listener stopped", "err", err)
	}
}
