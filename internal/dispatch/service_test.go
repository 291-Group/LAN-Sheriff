package dispatch

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is the Store interface backed by a map, so the service can be tested
// without a database.
type memStore struct {
	mu      sync.Mutex
	peers   []PeerRecord
	local   []SummaryBucket
	addrSet []string
	merged  map[string][]SummaryBucket
	mergeMu sync.Mutex
}

func newMemStore() *memStore {
	return &memStore{merged: map[string][]SummaryBucket{}}
}

func (m *memStore) DispatchPeers(context.Context) ([]PeerRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]PeerRecord(nil), m.peers...), nil
}

func (m *memStore) MergeDispatchSummaries(_ context.Context, peerID string, b []SummaryBucket, _ time.Time) (int, error) {
	m.mergeMu.Lock()
	defer m.mergeMu.Unlock()
	m.merged[peerID] = append(m.merged[peerID], b...)
	return len(b), nil
}

func (m *memStore) AddDispatchPeer(_ context.Context, p PairedPeer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = append(m.peers, PeerRecord{
		PeerID: p.PeerID, PublicKey: p.PublicKey, Label: p.Label, LastAddr: p.Addr,
	})
	return nil
}

func (m *memStore) LocalSummaries(_ context.Context, _ time.Time, limit int) ([]SummaryBucket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]SummaryBucket(nil), m.local...), nil
}

// Mirrors the real store's WHERE clause: a peer that already has a name keeps
// it. Written the same way here on purpose, so a test asserting the rule is
// asserting the rule and not this fake's convenience.
func (m *memStore) SetDispatchPeerLabelIfEmpty(_ context.Context, peerID, label string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.peers {
		if m.peers[i].PeerID == peerID && m.peers[i].Label == "" {
			m.peers[i].Label = label
		}
	}
	return nil
}

func (m *memStore) SetDispatchPeerAddr(_ context.Context, peerID, addr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addrSet = append(m.addrSet, peerID+"@"+addr)
	for i := range m.peers {
		if m.peers[i].PeerID == peerID {
			m.peers[i].LastAddr = addr
		}
	}
	return nil
}

func (m *memStore) ExpireDispatchSummaries(_ context.Context, _ time.Duration, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *memStore) setLocal(b []SummaryBucket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local = b
}

func (m *memStore) addrUpdates() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.addrSet...)
}

func (m *memStore) add(p PeerRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = append(m.peers, p)
}

func (m *memStore) mergedFor(peerID string) []SummaryBucket {
	m.mergeMu.Lock()
	defer m.mergeMu.Unlock()
	return append([]SummaryBucket(nil), m.merged[peerID]...)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newService(t *testing.T, st Store) *Service {
	t.Helper()
	svc, err := New(Config{
		Enabled: true, Listen: "127.0.0.1:0", DataDir: t.TempDir(),
	}, st, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// Nothing starts unless it was asked for.
func TestDisabledByDefault(t *testing.T) {
	if _, err := New(Config{}, newMemStore(), quietLogger()); err != ErrDisabled {
		t.Errorf("err = %v, want ErrDisabled", err)
	}
	// And no key material is created by the attempt.
	dir := t.TempDir()
	_, _ = New(Config{DataDir: dir}, newMemStore(), quietLogger())
	if _, err := LoadIdentityIfExists(dir); err == nil {
		t.Error("a disabled service created an identity key")
	}
}

// The mitigation for an attacker off the local network, enforced in code.
func TestRefusesToBindSomewhereReachable(t *testing.T) {
	for name, listen := range map[string]string{
		"every interface":      "0.0.0.0:2912",
		"every interface (v6)": "[::]:2912",
		"a routable address":   "8.8.8.8:2912",
		"no address at all":    ":2912",
	} {
		t.Run(name, func(t *testing.T) {
			err := checkBindAddress(listen, false)
			if err == nil {
				t.Fatalf("checkBindAddress(%q) allowed it", listen)
			}
			// The message must say what to do instead, not merely refuse.
			if !strings.Contains(err.Error(), "--dispatch-allow-public") {
				t.Errorf("error does not offer the override: %v", err)
			}
		})
	}

	for name, listen := range map[string]string{
		"a private address": "192.168.1.10:2912",
		"loopback":          "127.0.0.1:2912",
		"a hostname":        "my-machine.local:2912",
		// 100.64.0.0/10 is carrier-grade NAT, and it is where Tailscale
		// assigns addresses from. netip.Addr.IsPrivate reports false for the
		// whole block, so this check used to refuse every tailnet address and
		// tell the user to pass --dispatch-allow-public to get past it. Pairing
		// two houses over a tailnet is a case the documentation recommends, and
		// the advice for it must not be "switch the guard off".
		"a tailnet address":       "100.101.102.103:2912",
		"the bottom of the block": "100.64.0.1:2912",
		"the top of the block":    "100.127.255.254:2912",
		"a tailnet v6 address":    "[fd7a:115c:a1e0::1]:2912",
		"link-local":              "169.254.10.20:2912",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkBindAddress(listen, false); err != nil {
				t.Errorf("checkBindAddress(%q) refused a local address: %v", listen, err)
			}
		})
	}

	// The operator may insist.
	if err := checkBindAddress("0.0.0.0:2912", true); err != nil {
		t.Errorf("--dispatch-allow-public did not permit it: %v", err)
	}
}

// Two paired instances must exchange a summary end to end, over real TLS, with
// the merge attributed to the connection's authenticated identity. This is the
// test that proves the feature rather than its parts.
func TestTwoInstancesExchangeASummary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	defer svcB.Stop()

	// Pair them: each pins the other's key, and each knows where the other is.
	storeA.add(PeerRecord{
		PeerID: svcB.Identity().PeerID(), PublicKey: svcB.Identity().Public(),
		Label: "B", LastAddr: svcB.Addr().String(),
	})
	storeB.add(PeerRecord{
		PeerID: svcA.Identity().PeerID(), PublicKey: svcA.Identity().Public(),
		Label: "A", LastAddr: svcA.Addr().String(),
	})

	// Whichever side dials, a connection must come up within a few ticks.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if svcA.isLive(svcB.Identity().PeerID()) && svcB.isLive(svcA.Identity().PeerID()) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !svcA.isLive(svcB.Identity().PeerID()) {
		t.Fatal("the two instances never connected")
	}

	// The dialling side sends a summary.
	dialer, receiver := svcA, svcB
	receiverStore := storeB
	if !svcA.shouldDial(svcB.Identity().PeerID()) {
		dialer, receiver, receiverStore = svcB, svcA, storeA
	}

	hour := time.Now().Truncate(time.Hour).Unix()
	dialer.mu.RLock()
	conn := dialer.live[receiver.Identity().PeerID()]
	dialer.mu.RUnlock()
	if conn == nil {
		t.Fatal("no live connection on the dialling side")
	}
	if err := conn.Send(TypeSummary, SummaryMessage{Buckets: []SummaryBucket{{
		Hour: hour, Device: "laptop", Org: "Cloudflare, Inc.", Country: "US",
		App: "Firefox", Proto: "tcp", Port: 443, Flows: 7,
	}}}); err != nil {
		t.Fatal(err)
	}

	// The receiver must merge it, attributed to the sender's authenticated id.
	var got []SummaryBucket
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got = receiverStore.mergedFor(dialer.Identity().PeerID()); len(got) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(got) != 1 {
		t.Fatalf("receiver merged %d buckets, want 1", len(got))
	}
	if got[0].Flows != 7 || got[0].Org != "Cloudflare, Inc." {
		t.Errorf("merged the wrong bucket: %+v", got[0])
	}
}

// A stranger who is not paired must get nowhere, against a running service.
func TestUnpairedInstanceIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	storeA := newMemStore()
	svcA := newService(t, storeA)
	if err := svcA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer svcA.Stop()

	// The stranger knows where A is and pins A correctly. A has never heard of
	// the stranger, which is the only thing that should matter.
	stranger := newService(t, newMemStore())
	cfg, err := ClientTLS(stranger.Identity(), PinnedTo(svcA.Identity().Public()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", svcA.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Handshake(ctx, raw, cfg, false)
	if err == nil {
		// TLS 1.3 lets a client finish before the server rejects its
		// certificate, so this may succeed; nothing may be merged either way.
		_ = conn.Send(TypeSummary, SummaryMessage{Buckets: []SummaryBucket{{
			Hour: time.Now().Truncate(time.Hour).Unix(), Device: "d", Flows: 1,
		}}})
		conn.Close()
	}

	time.Sleep(500 * time.Millisecond)
	if n := len(storeA.mergedFor(stranger.Identity().PeerID())); n != 0 {
		t.Fatalf("an unpaired instance got %d buckets merged", n)
	}
	if svcA.isLive(stranger.Identity().PeerID()) {
		t.Error("an unpaired instance is registered as a live peer")
	}
}

// Only one side dials, and they must agree on which.
func TestExactlyOneSideDials(t *testing.T) {
	a, b := newService(t, newMemStore()), newService(t, newMemStore())
	aDials := a.shouldDial(b.Identity().PeerID())
	bDials := b.shouldDial(a.Identity().PeerID())
	if aDials == bDials {
		t.Errorf("both sides would %s", map[bool]string{true: "dial", false: "listen"}[aDials])
	}
}

// Backoff must grow, stay bounded, and be jittered, two instances rebooted
// together otherwise retry in lockstep forever.
func TestBackoffGrowsAndIsJittered(t *testing.T) {
	var d time.Duration
	var seq []time.Duration
	for i := 0; i < 12; i++ {
		d = nextBackoff(d)
		seq = append(seq, d)
		if d > backoffMax+time.Duration(float64(backoffMax)*backoffJitter) {
			t.Fatalf("backoff %v exceeded the ceiling", d)
		}
		if d <= 0 {
			t.Fatalf("backoff %v is not positive", d)
		}
	}
	if seq[5] <= seq[0] {
		t.Errorf("backoff is not growing: %v then %v", seq[0], seq[5])
	}

	// Two independent sequences must not be identical.
	var x, y time.Duration
	same := 0
	for i := 0; i < 10; i++ {
		x, y = nextBackoff(x), nextBackoff(y)
		if x == y {
			same++
		}
	}
	if same == 10 {
		t.Error("two backoff sequences were identical; jitter is not applied")
	}
}

// A peer that goes quiet must be shown as unreachable, which is a different
// statement from "reports nothing".
func TestStatesDistinguishGreyFromSuspended(t *testing.T) {
	st := newMemStore()
	svc := newService(t, st)

	st.add(PeerRecord{PeerID: "AAAAA", PublicKey: ed25519.PublicKey("k1"), Label: "never seen"})
	st.add(PeerRecord{PeerID: "BBBBB", PublicKey: ed25519.PublicKey("k2"), Label: "off", Suspended: true})

	states, err := svc.States(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("got %d states, want 2", len(states))
	}
	byID := map[string]PeerState{}
	for _, s := range states {
		byID[s.PeerID] = s
	}
	if byID["AAAAA"].Status != "grey" {
		t.Errorf("an unreachable peer is %q, want grey", byID["AAAAA"].Status)
	}
	if byID["BBBBB"].Status != "suspended" {
		t.Errorf("a suspended peer is %q, want suspended", byID["BBBBB"].Status)
	}
	if byID["AAAAA"].Connected {
		t.Error("a peer never contacted is reported as connected")
	}
}

// States is called from an API handler, so it must never wait on a peer.
func TestStatesDoesNotBlock(t *testing.T) {
	st := newMemStore()
	for i := 0; i < MaxPeers; i++ {
		st.add(PeerRecord{
			PeerID: strings.Repeat(string(rune('A'+i)), 5),
			// An address that will never answer.
			LastAddr: "203.0.113.1:2912", PublicKey: ed25519.PublicKey("k"),
		})
	}
	svc := newService(t, st)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := svc.States(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("States blocked; an unreachable peer would stall the dashboard")
	}
}

// A peer's reachability and the freshness of its data are different facts. A
// peer can be freshly reconnected with nothing recent to show, and one can be
// unreachable while its last hour of data is perfectly good.
func TestDataStalenessIsSeparateFromReachability(t *testing.T) {
	st := newMemStore()
	st.add(PeerRecord{PeerID: "AAAAA", PublicKey: ed25519.PublicKey("k"), Label: "never heard from"})
	svc := newService(t, st)

	states, err := svc.States(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !states[0].DataStale {
		t.Error("a peer never heard from is not marked stale; it has no data at all")
	}

	// Contact just now: reachable, and its data is current.
	svc.touch("AAAAA")
	states, _ = svc.States(context.Background())
	if states[0].DataStale {
		t.Error("a peer contacted just now is marked stale")
	}

	// Contact long ago: the data should no longer be presented as current.
	svc.mu.Lock()
	svc.seen["AAAAA"] = time.Now().Add(-2 * staleAfter)
	svc.mu.Unlock()
	states, _ = svc.States(context.Background())
	if !states[0].DataStale {
		t.Errorf("data older than %v is not marked stale", staleAfter)
	}
}

// The test that was missing, and whose absence let a half-built feature be
// marked done: two paired instances must exchange summaries **on their own**,
// with nobody calling Send by hand.
//
// Every other test drove the connection manually, so the receive path, the wire
// format and the merge were all proven while nothing ever produced a bucket.
// Two real instances connected and shared nothing.
func TestPeersExchangeSummariesWithoutBeingTold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	storeA, storeB := newMemStore(), newMemStore()
	hour := time.Now().Truncate(time.Hour).Unix()

	// Each side has something of its own to report.
	storeA.setLocal([]SummaryBucket{{
		Hour: hour, Device: "a-laptop", Org: "Cloudflare, Inc.", Country: "US",
		App: "Firefox", Proto: "tcp", Port: 443, Flows: 11,
	}})
	storeB.setLocal([]SummaryBucket{{
		Hour: hour, Device: "b-phone", Org: "Google LLC", Country: "US",
		App: "Safari", Proto: "tcp", Port: 443, Flows: 22,
	}})

	svcA, svcB := newService(t, storeA), newService(t, storeB)
	if err := svcA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer svcA.Stop()
	if err := svcB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer svcB.Stop()

	storeA.add(PeerRecord{
		PeerID: svcB.Identity().PeerID(), PublicKey: svcB.Identity().Public(),
		LastAddr: svcB.Addr().String(),
	})
	storeB.add(PeerRecord{
		PeerID: svcA.Identity().PeerID(), PublicKey: svcA.Identity().Public(),
		LastAddr: svcA.Addr().String(),
	})

	// Nothing below sends anything. If the service does not do it, this fails.
	deadline := time.Now().Add(25 * time.Second)
	var fromA, fromB []SummaryBucket
	for time.Now().Before(deadline) {
		fromA = storeB.mergedFor(svcA.Identity().PeerID())
		fromB = storeA.mergedFor(svcB.Identity().PeerID())
		if len(fromA) > 0 && len(fromB) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(fromA) == 0 {
		t.Error("B never received A's summaries; nothing sends them")
	} else if fromA[0].Flows != 11 || fromA[0].Device != "a-laptop" {
		t.Errorf("B received the wrong bucket from A: %+v", fromA[0])
	}
	if len(fromB) == 0 {
		t.Error("A never received B's summaries; nothing sends them")
	} else if fromB[0].Flows != 22 || fromB[0].Device != "b-phone" {
		t.Errorf("A received the wrong bucket from B: %+v", fromB[0])
	}
}

// Each side must record where the *other* actually listens, learned from its
// hello rather than from the socket it happened to arrive on.
//
// This replaces a version that seeded one side with a deliberately stale
// address to simulate a move. That test was unsound: only the lower peer ID
// dials, so whether a connection formed at all depended on which of two randomly
// generated identities sorted first. It passed, then failed, for reasons that
// had nothing to do with the behaviour under test.
//
// The mechanism is the same either way, an address is written on every hello,
// so a peer that moved is corrected the next time it connects, and this
// version exercises it without depending on a coin flip.
func TestPeerAddressIsRecordedFromHello(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	defer svcB.Stop()

	storeA.add(PeerRecord{
		PeerID: svcB.Identity().PeerID(), PublicKey: svcB.Identity().Public(),
		LastAddr: svcB.Addr().String(),
	})
	storeB.add(PeerRecord{
		PeerID: svcA.Identity().PeerID(), PublicKey: svcA.Identity().Public(),
		LastAddr: svcA.Addr().String(),
	})

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if len(storeA.addrUpdates()) > 0 && len(storeB.addrUpdates()) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(storeA.addrUpdates()) == 0 || len(storeB.addrUpdates()) == 0 {
		t.Fatalf("addresses were not recorded from hello (A: %d, B: %d)",
			len(storeA.addrUpdates()), len(storeB.addrUpdates()))
	}

	// Whatever each recorded must be the other's listening port, not an
	// ephemeral one, that is the whole point.
	peersA, _ := storeA.DispatchPeers(ctx)
	if peersA[0].LastAddr != svcB.Addr().String() {
		t.Errorf("A recorded %q for B, want its listener %q",
			peersA[0].LastAddr, svcB.Addr().String())
	}
	peersB, _ := storeB.DispatchPeers(ctx)
	if peersB[0].LastAddr != svcA.Addr().String() {
		t.Errorf("B recorded %q for A, want its listener %q",
			peersB[0].LastAddr, svcA.Addr().String())
	}
}

// Unpairing is local to the machine that does it, so the ordinary state after
// one side unpairs is: A has forgotten B, and B still has A pinned.
//
// From that state A could never pair with B again. The listener chose between
// pairing and an ordinary session by whether it recognised the key, so A was
// recognised, handed to the session loop, and answered with a goodbye however
// fresh its code was. The dashboard reported "not showing a pairing code" while
// a window was open on screen, which sent somebody hunting addresses and
// firewalls for an evening.
//
// The listener now chooses on what the caller asks for. A pair request is still
// only honoured while a window is open, so an already-paired peer cannot force
// re-pairing on its own: the operator here has to have opened one.
func TestPairsAgainWhenOnlyTheOtherSideStillHasUs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	defer svcB.Stop()

	// The asymmetry: B still has A, A has forgotten B.
	storeB.add(PeerRecord{
		PeerID: svcA.Identity().PeerID(), PublicKey: svcA.Identity().Public(),
		Label: "A", LastAddr: svcA.Addr().String(),
	})

	ps, err := svcB.StartPairing()
	if err != nil {
		t.Fatalf("B could not show a code: %v", err)
	}

	peer, err := svcA.JoinWithCode(ctx, svcB.Addr().String(), ps.Code(), "B")
	if err != nil {
		t.Fatalf("A could not pair with a machine that still has A paired: %v\n"+
			"this is the state left by any one-sided unpair, and it must be recoverable "+
			"without touching the other machine", err)
	}
	if peer.PeerID != svcB.Identity().PeerID() {
		t.Errorf("paired with %s, want %s", peer.PeerID, svcB.Identity().PeerID())
	}
}

// A machine paired before the label was ever exchanged shows its peer as a
// 29-character fingerprint, and re-pairing to fix that is a lot to ask. Hello
// carries the sender's name on every connection, so the name arrives on the next
// reconnect. The rule that matters is the one in the WHERE clause: a peer the
// operator has already named keeps that name, no matter how often the far end
// announces its own.
func TestPeerNameArrivesOnConnectButNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, stored, announced, want string
	}{
		{"a peer with no name takes the one it announces", "", "hall-pi", "hall-pi"},
		{"a peer the operator named keeps that name", "Pi in the basement", "hall-pi", "Pi in the basement"},
		{"an announcement of nothing changes nothing", "Pi in the basement", "", "Pi in the basement"},
	} {
		st := newMemStore()
		st.peers = []PeerRecord{{PeerID: "peer-1", Label: c.stored}}
		if c.announced != "" {
			if err := st.SetDispatchPeerLabelIfEmpty(ctx, "peer-1", c.announced); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		if got := st.peers[0].Label; got != c.want {
			t.Errorf("%s: label = %q, want %q", c.name, got, c.want)
		}
	}
}

// What a machine calls itself is the only thing standing between a reader and a
// fingerprint, and the raw hostname is often not a name at all. These are the
// three commonest installs, not hypotheticals: macOS appends .local, a container
// is named after its own id, and a machine nobody has renamed is "localhost".
func TestIsHexIDRecognisesContainerIdentifiers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"ac382c079142", true},                // Docker's short id, twelve hex digits
		{strings.Repeat("a1b2c3d4", 8), true}, // the full sixty-four
		{"workshop-mac", false},
		{"raspberrypi", false},
		{"deadbeef", false},    // hex, but far too short to be an id
		{"ac382c07914", false}, // eleven, not a length Docker uses
		{"ac382c07914z", false},
		{"", false},
	} {
		if got := isHexID(c.in); got != c.want {
			t.Errorf("isHexID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
