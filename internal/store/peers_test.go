package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func addTestPeer(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.AddPeer(context.Background(), Peer{
		PeerID: id, PublicKey: []byte("key-" + id), Label: "Peer " + id,
	}); err != nil {
		t.Fatal(err)
	}
}

func bucket(device, org string, hour int64, flows int64) PeerSummary {
	return PeerSummary{
		Device: device, Hour: hour, Org: org, Country: "US", ASN: 13335,
		App: "Firefox", Proto: "tcp", Port: 443, Flows: flows,
	}
}

func TestPeerRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")

	peers, err := s.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if peers[0].Trust != PeerTrusted {
		t.Errorf("trust = %q, want %q", peers[0].Trust, PeerTrusted)
	}
	if peers[0].PairedAt.IsZero() {
		t.Error("paired_at was not recorded")
	}
}

// The rule that confines a compromised peer to lying about itself.
func TestPeerCannotWriteAnotherPeersRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	addTestPeer(t, s, "PEER-B")

	forged := bucket("victim-device", "Evil Corp", hourOf(time.Now()), 99)
	forged.PeerID = "PEER-B" // A claims to be reporting on B's behalf

	_, err := s.MergePeerSummaries(ctx, "PEER-A", []PeerSummary{forged}, time.Now())
	if err == nil {
		t.Fatal("a peer wrote a summary attributed to a different peer")
	}
	// The message must name both peers, since this is the log line somebody
	// investigates a compromise from.
	for _, want := range []string{"PEER-A", "PEER-B", "only report about itself"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// Two peers using the same device identifier are two different machines.
func TestSameDeviceIDFromTwoPeersStaysSeparate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	addTestPeer(t, s, "PEER-B")
	h := hourOf(time.Now())

	if _, err := s.MergePeerSummaries(ctx, "PEER-A",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 10)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergePeerSummaries(ctx, "PEER-B",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 20)}, time.Now()); err != nil {
		t.Fatal(err)
	}

	got, err := s.PeerSummariesSince(ctx, time.Unix(h-3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2, one peer's data overwrote another's", len(got))
	}
	seen := map[string]int64{}
	for _, b := range got {
		seen[b.PeerID] = b.Flows
	}
	if seen["PEER-A"] != 10 || seen["PEER-B"] != 20 {
		t.Errorf("rows crossed between peers: %v", seen)
	}
}

// A peer restating an hour is recomputing a total, not adding to one. Summing
// would let a peer inflate its numbers without limit by resending.
func TestResendingReplacesRatherThanAccumulates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	h := hourOf(time.Now())

	for _, flows := range []int64{10, 25, 25} {
		if _, err := s.MergePeerSummaries(ctx, "PEER-A",
			[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, flows)}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.PeerSummariesSince(ctx, time.Unix(h-3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].Flows != 25 {
		t.Errorf("flows = %d, want 25 (replaced, not summed to 60)", got[0].Flows)
	}
}

// An unpaired peer cannot write at all.
func TestUnpairedPeerCannotWrite(t *testing.T) {
	s := newTestStore(t)
	_, err := s.MergePeerSummaries(context.Background(), "NEVER-PAIRED",
		[]PeerSummary{bucket("d", "o", hourOf(time.Now()), 1)}, time.Now())
	if !errors.Is(err, ErrUnknownPeer) {
		t.Errorf("error = %v, want ErrUnknownPeer", err)
	}
}

// Suspension stops the data without ending the pairing.
func TestSuspendedPeerIsNotBelieved(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	h := hourOf(time.Now())

	if _, err := s.MergePeerSummaries(ctx, "PEER-A",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 10)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPeerTrust(ctx, "PEER-A", PeerSuspended); err != nil {
		t.Fatal(err)
	}

	// Existing data disappears from reads...
	got, err := s.PeerSummariesSince(ctx, time.Unix(h-3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a suspended peer's data is still being read: %d rows", len(got))
	}

	// ...new data is refused...
	if _, err := s.MergePeerSummaries(ctx, "PEER-A",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 50)}, time.Now()); !errors.Is(err, ErrPeerSuspended) {
		t.Errorf("error = %v, want ErrPeerSuspended", err)
	}

	// ...and the pairing itself survives, which is the point of suspending.
	peers, err := s.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatal("suspending removed the pairing")
	}

	// Un-suspending restores the history rather than needing it re-sent.
	if err := s.SetPeerTrust(ctx, "PEER-A", PeerTrusted); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PeerSummariesSince(ctx, time.Unix(h-3600, 0))
	if len(got) != 1 {
		t.Errorf("un-suspending did not restore the peer's history: %d rows", len(got))
	}
}

// Unpairing must remove the data too, or the operator's decision has no effect.
func TestUnpairingRemovesTheData(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	h := hourOf(time.Now())

	if _, err := s.MergePeerSummaries(ctx, "PEER-A",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 10)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePeer(ctx, "PEER-A"); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM peer_summaries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d summary rows survived unpairing", n)
	}
	peers, _ := s.Peers(ctx)
	if len(peers) != 0 {
		t.Error("the peer record survived unpairing")
	}
}

// Peer data is a cache, not a record.
func TestPeerSummariesExpire(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	h := hourOf(time.Now())

	old := time.Now().Add(-30 * 24 * time.Hour)
	if _, err := s.MergePeerSummaries(ctx, "PEER-A",
		[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 10)}, old); err != nil {
		t.Fatal(err)
	}

	n, err := s.ExpirePeerSummaries(ctx, 7*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expired %d rows, want 1", n)
	}
}

func TestSetPeerTrustRejectsNonsense(t *testing.T) {
	s := newTestStore(t)
	addTestPeer(t, s, "PEER-A")
	if err := s.SetPeerTrust(context.Background(), "PEER-A", "god-mode"); err == nil {
		t.Error("an unknown trust state was accepted")
	}
	if err := s.SetPeerTrust(context.Background(), "NOBODY", PeerTrusted); !errors.Is(err, ErrUnknownPeer) {
		t.Errorf("error = %v, want ErrUnknownPeer", err)
	}
}

// Nothing peer-related may exist until peering is used.
func TestPeerTablesStartEmpty(t *testing.T) {
	s := newTestStore(t)
	peers, err := s.Peers(context.Background())
	if err != nil {
		t.Fatalf("the peers table is missing entirely: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("a fresh database already has %d peers", len(peers))
	}
	got, err := s.PeerSummariesSince(context.Background(), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a fresh database already has %d peer summaries", len(got))
	}
}

func hourOf(t time.Time) int64 { return t.Truncate(time.Hour).Unix() }

// The read path the dashboard uses must apply the trust filter too. A read that
// forgot it would silently reintroduce data the operator chose to stop
// believing, which is the whole point of suspending rather than unpairing.
func TestPeerDestinationsRespectTrust(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addTestPeer(t, s, "PEER-A")
	addTestPeer(t, s, "PEER-B")
	h := hourOf(time.Now())

	for _, p := range []string{"PEER-A", "PEER-B"} {
		if _, err := s.MergePeerSummaries(ctx, p,
			[]PeerSummary{bucket("laptop", "Cloudflare, Inc.", h, 5)}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.PeerDestinations(ctx, time.Unix(h-3600, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d destinations, want 2", len(got))
	}
	// The label is what a person reads, so it must be carried through rather
	// than leaving the caller to join it back on.
	if got[0].Label == "" || got[0].Label == got[0].PeerID {
		t.Errorf("destination has no readable label: %+v", got[0])
	}

	if err := s.SetPeerTrust(ctx, "PEER-B", PeerSuspended); err != nil {
		t.Fatal(err)
	}
	got, err = s.PeerDestinations(ctx, time.Unix(h-3600, 0), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d destinations after suspending one peer, want 1", len(got))
	}
	if got[0].PeerID != "PEER-A" {
		t.Errorf("the wrong peer survived suspension: %s", got[0].PeerID)
	}
}

// Unpairing removes the peer and its data, and must not remove the record that
// the pairing ever happened.
//
// This is the whole point of the ledger. Unpairing is the right way to stop
// trusting a machine, and it deletes everything that machine reported, which
// also means that afterwards nothing could answer "was this computer ever
// sharing with anyone". The person most likely to ask is the one who did not
// install the software.
func TestPairingLedgerOutlivesThePairing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddPeer(ctx, Peer{
		PeerID: "PEER-ONE", PublicKey: []byte("k"), Label: "Upstairs", LastAddr: "192.168.1.9:2912",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePeer(ctx, "PEER-ONE"); err != nil {
		t.Fatal(err)
	}

	peers, err := s.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("the peer survived unpairing: %+v", peers)
	}

	history, err := s.PairingHistory(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history has %d entries, want a pairing and an unpairing: %+v", len(history), history)
	}
	if history[0].Event != "unpaired" || history[1].Event != "paired" {
		t.Errorf("events are %q then %q, want unpaired then paired (newest first)",
			history[0].Event, history[1].Event)
	}
	// The label is what makes an entry readable months later; losing it with the
	// peer row would leave a bare identifier nobody can interpret.
	for _, e := range history {
		if e.Peer != "PEER-ONE" {
			t.Errorf("peer id = %q", e.Peer)
		}
		if e.Label != "Upstairs" {
			t.Errorf("%s entry lost the label: %q", e.Event, e.Label)
		}
	}
}
