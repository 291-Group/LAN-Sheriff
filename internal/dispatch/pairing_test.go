package dispatch

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// startPairable brings up a service with a pairing window already open, and
// returns it with the code to type into the other machine.
func startPairable(t *testing.T, ctx context.Context) (*Service, *memStore, string) {
	t.Helper()
	st := newMemStore()
	svc := newService(t, st)
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ps, err := svc.StartPairing()
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, ps.Code()
}

// The whole point: two strangers become peers, both sides record it, and both
// end up holding the other's real key.
func TestPairingWithACodeSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	displayer, dispStore, code := startPairable(t, ctx)
	defer displayer.Stop()

	joiner := newService(t, newMemStore())
	defer joiner.Stop()

	peer, err := joiner.JoinWithCode(ctx, displayer.Addr().String(), code, "Joiner")
	if err != nil {
		t.Fatalf("pairing failed: %v", err)
	}
	if peer.PeerID != displayer.Identity().PeerID() {
		t.Errorf("joiner recorded %q, want %q", peer.PeerID, displayer.Identity().PeerID())
	}

	// The displaying side must have recorded the joiner too.
	deadline := time.Now().Add(5 * time.Second)
	var recorded []PeerRecord
	for time.Now().Before(deadline) {
		recorded, _ = dispStore.DispatchPeers(ctx)
		if len(recorded) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(recorded) != 1 {
		t.Fatalf("the displaying side recorded %d peers, want 1", len(recorded))
	}
	if recorded[0].PeerID != joiner.Identity().PeerID() {
		t.Errorf("displayer recorded %q, want %q", recorded[0].PeerID, joiner.Identity().PeerID())
	}
	if !recorded[0].PublicKey.Equal(joiner.Identity().Public()) {
		t.Error("the displayer pinned the wrong key")
	}
}

// A wrong code must not pair, and must not leave a peer behind.
func TestWrongCodeDoesNotPair(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	displayer, dispStore, _ := startPairable(t, ctx)
	defer displayer.Stop()

	// A syntactically valid code for the right machine, with the wrong secret.
	other, err := NewJoinCode(displayer.Identity().Public())
	if err != nil {
		t.Fatal(err)
	}

	joiner := newService(t, newMemStore())
	defer joiner.Stop()

	_, err = joiner.JoinWithCode(ctx, displayer.Addr().String(), other.String(), "Joiner")
	if err == nil {
		t.Fatal("a wrong code paired successfully")
	}
	time.Sleep(300 * time.Millisecond)
	if got, _ := dispStore.DispatchPeers(ctx); len(got) != 0 {
		t.Errorf("a failed pairing left %d peers behind", len(got))
	}
}

// One failure burns the window. There is no legitimate reason to get a code
// wrong against the machine that just displayed it, so a second attempt is
// treated as an attempt rather than a typo.
//
// **Two independent mechanisms produce this**, and that was established by
// experiment rather than assumed: `takePairing` removes the session from the
// service on the first connection, and `PairingSession.claim` separately marks
// the code consumed. Removing *either* alone leaves this test passing, because
// the other still closes the window. Removing both makes it fail.
//
// That redundancy is the point, this is the control that turns a 128-bit
// secret into a real barrier rather than something guessable at leisure, but it
// does mean this test cannot attribute the behaviour to one mechanism.
// TestSessionExpiryAndCancel/one_claim_only covers `claim` on its own.
func TestOneFailureBurnsTheCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	displayer, _, realCode := startPairable(t, ctx)
	defer displayer.Stop()

	wrong, err := NewJoinCode(displayer.Identity().Public())
	if err != nil {
		t.Fatal(err)
	}

	attacker := newService(t, newMemStore())
	defer attacker.Stop()
	if _, err := attacker.JoinWithCode(ctx, displayer.Addr().String(), wrong.String(), "attacker"); err == nil {
		t.Fatal("a wrong code succeeded")
	}

	// Now the real code must no longer work: the window is spent.
	honest := newService(t, newMemStore())
	defer honest.Stop()
	if _, err := honest.JoinWithCode(ctx, displayer.Addr().String(), realCode, "honest"); err == nil {
		t.Fatal("the correct code still worked after a failed attempt burned the window")
	}
}

// With no window open, an unpinned machine gets nowhere at all.
func TestNoPairingWindowMeansNoEntry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st := newMemStore()
	svc := newService(t, st)
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()

	// A well-formed code for this machine, but nobody opened a window.
	code, err := NewJoinCode(svc.Identity().Public())
	if err != nil {
		t.Fatal(err)
	}
	joiner := newService(t, newMemStore())
	defer joiner.Stop()

	if _, err := joiner.JoinWithCode(ctx, svc.Addr().String(), code.String(), "joiner"); err == nil {
		t.Fatal("paired with no pairing window open")
	}
	if got, _ := st.DispatchPeers(ctx); len(got) != 0 {
		t.Errorf("%d peers recorded with no window open", len(got))
	}
}

// A code for one machine must not be usable against another, this is the tag
// check, and it must fail before the joiner discloses its proof.
func TestCodeIsBoundToItsMachine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Two machines, both with windows open; the code from the first is offered
	// to the second.
	_, _, codeForA := startPairable(t, ctx)
	svcB, storeB, _ := startPairable(t, ctx)
	defer svcB.Stop()

	joiner := newService(t, newMemStore())
	defer joiner.Stop()

	_, err := joiner.JoinWithCode(ctx, svcB.Addr().String(), codeForA, "joiner")
	if !errors.Is(err, ErrWrongMachine) {
		t.Fatalf("err = %v, want ErrWrongMachine", err)
	}
	if got, _ := storeB.DispatchPeers(ctx); len(got) != 0 {
		t.Errorf("the wrong machine recorded %d peers", len(got))
	}
}

func TestSessionExpiryAndCancel(t *testing.T) {
	id, err := LoadIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expires with time", func(t *testing.T) {
		ps, _ := NewPairingSession(id, time.Now())
		if ps.expired(time.Now()) {
			t.Error("a fresh session is already expired")
		}
		if !ps.expired(time.Now().Add(PairingWindow + time.Second)) {
			t.Error("the session outlived its window")
		}
		if _, err := ps.claim(time.Now().Add(PairingWindow + time.Second)); !errors.Is(err, ErrPairingExpired) {
			t.Errorf("claim error = %v, want ErrPairingExpired", err)
		}
	})

	t.Run("cancel closes it immediately", func(t *testing.T) {
		ps, _ := NewPairingSession(id, time.Now())
		ps.Cancel()
		if !ps.expired(time.Now()) {
			t.Error("a cancelled session is still open")
		}
		if _, err := ps.claim(time.Now()); !errors.Is(err, ErrPairingUsed) {
			t.Errorf("claim error = %v, want ErrPairingUsed", err)
		}
	})

	t.Run("one claim only", func(t *testing.T) {
		ps, _ := NewPairingSession(id, time.Now())
		if _, err := ps.claim(time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := ps.claim(time.Now()); !errors.Is(err, ErrPairingUsed) {
			t.Errorf("a second claim succeeded: %v", err)
		}
	})
}

// Only one window at a time: two would mean two unpinned keys admitted at once.
func TestOnlyOnePairingWindowAtATime(t *testing.T) {
	svc := newService(t, newMemStore())
	if _, err := svc.StartPairing(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartPairing(); err == nil {
		t.Error("a second pairing window opened while one was already showing")
	}
	svc.CancelPairing()
	if _, err := svc.StartPairing(); err != nil {
		t.Errorf("could not open a window after cancelling: %v", err)
	}
}

// After pairing, **both** sides must hold an address the other can actually be
// dialled at.
//
// The first version recorded the joiner's ephemeral source port on the
// displaying side, so a freshly paired pair never connected whenever the
// displayer was the side that dials. Everything looked correct, both sides
// showed the pairing, both had the right key, and nothing ever happened.
func TestBothSidesRecordADialableAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	displayer, dispStore, code := startPairable(t, ctx)
	defer displayer.Stop()

	joinStore := newMemStore()
	joiner := newService(t, joinStore)
	if err := joiner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer joiner.Stop()

	if _, err := joiner.JoinWithCode(ctx, displayer.Addr().String(), code, "Joiner"); err != nil {
		t.Fatal(err)
	}

	var recorded []PeerRecord
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		recorded, _ = dispStore.DispatchPeers(ctx)
		if len(recorded) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(recorded) != 1 {
		t.Fatalf("the displayer recorded %d peers, want 1", len(recorded))
	}

	// The address the displayer holds must be the joiner's *listener*.
	want := joiner.Addr().String()
	if recorded[0].LastAddr != want {
		t.Errorf("displayer recorded %q, want the joiner's listening address %q "+
			"(an ephemeral source port here means the two can never connect)",
			recorded[0].LastAddr, want)
	}
}

// A peer may choose its own port and nothing else. Letting it name a host would
// hand a redirect primitive to the one participant the merge rules already
// assume may be compromised.
func TestPeerCannotRedirectUsToAnotherHost(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("192.168.1.50"), Port: 54321}

	got := dialAddr(remote, 2912)
	if got != "192.168.1.50:2912" {
		t.Errorf("dialAddr = %q, want the observed host with the claimed port", got)
	}

	for name, port := range map[string]int{
		"zero":     0,
		"negative": -1,
		"too big":  70000,
	} {
		t.Run(name, func(t *testing.T) {
			if got := dialAddr(remote, port); got != "" {
				t.Errorf("dialAddr with a %s port returned %q, want empty", name, got)
			}
		})
	}
}
