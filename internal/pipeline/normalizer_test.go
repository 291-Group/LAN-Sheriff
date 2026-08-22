package pipeline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

func conn(src, dst string, proto types.Proto) types.Conn {
	return types.Conn{
		Src:      netip.MustParseAddrPort(src),
		Dst:      netip.MustParseAddrPort(dst),
		Proto:    proto,
		DeviceID: "self-test",
	}
}

func snapshot(ts time.Time, conns ...types.Conn) types.RawEvent {
	return types.RawEvent{
		Kind:     types.KindConnSnapshot,
		Source:   "deputy",
		TS:       ts,
		Snapshot: conns,
	}
}

func TestSnapshotOpensAndClosesFlows(t *testing.T) {
	n := NewNormalizer()
	n.GraceRounds = 2
	t0 := time.Unix(1700000000, 0)

	a := conn("192.168.1.5:5000", "93.184.216.34:443", types.ProtoTCP)
	b := conn("192.168.1.5:5001", "1.1.1.1:443", types.ProtoTCP)

	events := n.Apply(snapshot(t0, a, b))
	if len(events) != 2 {
		t.Fatalf("first snapshot: got %d events, want 2", len(events))
	}
	for _, e := range events {
		if e.Phase != PhaseOpen {
			t.Errorf("first sighting should open, got %q", e.Phase)
		}
	}

	// Same connections again: updates, not reopens.
	events = n.Apply(snapshot(t0.Add(2*time.Second), a, b))
	for _, e := range events {
		if e.Phase != PhaseUpdate {
			t.Errorf("second sighting should update, got %q", e.Phase)
		}
	}
	if n.Len() != 2 {
		t.Errorf("tracking %d flows, want 2", n.Len())
	}

	// b disappears. One missed round is inside the grace period, so nothing
	// should close yet, this is the check that stops UDP flicker from
	// producing a close/open pair every few seconds.
	events = n.Apply(snapshot(t0.Add(4*time.Second), a))
	for _, e := range events {
		if e.Phase == PhaseClose {
			t.Error("closed inside the grace period")
		}
	}

	// Second consecutive miss: now it closes.
	events = n.Apply(snapshot(t0.Add(6*time.Second), a))
	var closed int
	for _, e := range events {
		if e.Phase == PhaseClose {
			closed++
			if e.Flow.DstIP != "1.1.1.1" {
				t.Errorf("closed the wrong flow: %s", e.Flow.DstIP)
			}
			if e.Flow.Active {
				t.Error("closed flow still marked active")
			}
		}
	}
	if closed != 1 {
		t.Errorf("closed %d flows, want 1", closed)
	}
	if n.Len() != 1 {
		t.Errorf("tracking %d flows after close, want 1", n.Len())
	}
}

func TestReturningFlowReopens(t *testing.T) {
	n := NewNormalizer()
	n.GraceRounds = 1
	t0 := time.Unix(1700000000, 0)
	c := conn("192.168.1.5:5000", "93.184.216.34:443", types.ProtoTCP)

	n.Apply(snapshot(t0, c))
	n.Apply(snapshot(t0.Add(time.Second)))

	events := n.Apply(snapshot(t0.Add(2*time.Second), c))
	if len(events) != 1 || events[0].Phase != PhaseOpen {
		t.Fatalf("a flow seen again after closing should open afresh, got %+v", events)
	}
}

func TestListenersAndHalfFormedEntriesAreNotFlows(t *testing.T) {
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)

	cases := []struct {
		name string
		c    types.Conn
	}{
		{"listening socket", conn("0.0.0.0:8080", "0.0.0.0:0", types.ProtoTCP)},
		{"bound udp socket", conn("192.168.1.5:5353", "0.0.0.0:0", types.ProtoUDP)},
		{"zero remote port", conn("192.168.1.5:5000", "93.184.216.34:0", types.ProtoTCP)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if events := n.Apply(snapshot(t0, tc.c)); len(events) != 0 {
				t.Errorf("got %d events, want 0", len(events))
			}
		})
	}
}

func TestLateProcessAttributionIsAdopted(t *testing.T) {
	// A socket can appear in the table a moment before we manage to map it to
	// its owning process; the attribution must not be lost when it arrives.
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)

	c := conn("192.168.1.5:5000", "93.184.216.34:443", types.ProtoTCP)
	n.Apply(snapshot(t0, c))

	withProc := c
	withProc.Process, withProc.PID = "Firefox", 42
	events := n.Apply(snapshot(t0.Add(time.Second), withProc))

	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if got := events[0].Flow.Process; got != "Firefox" {
		t.Errorf("process = %q, want Firefox", got)
	}
	if got := events[0].Flow.PID; got != 42 {
		t.Errorf("pid = %d, want 42", got)
	}
}

func TestByteCountersNeverGoBackwards(t *testing.T) {
	// Polling sources report cumulative counters and streaming sources report
	// deltas; neither should be able to make a flow's total shrink.
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)

	c := conn("192.168.1.5:5000", "93.184.216.34:443", types.ProtoTCP)
	c.BytesOut, c.BytesIn = 500, 1000
	n.Apply(snapshot(t0, c))

	lower := c
	lower.BytesOut, lower.BytesIn = 100, 200
	events := n.Apply(snapshot(t0.Add(time.Second), lower))

	if got := events[0].Flow.BytesOut; got != 500 {
		t.Errorf("bytes_out = %d, want 500", got)
	}
	if got := events[0].Flow.BytesIn; got != 1000 {
		t.Errorf("bytes_in = %d, want 1000", got)
	}
}

func TestFlowsFromDifferentSourcesDoNotCollide(t *testing.T) {
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)
	c := conn("192.168.1.5:5000", "93.184.216.34:443", types.ProtoTCP)

	n.Apply(types.RawEvent{Kind: types.KindConnSnapshot, Source: "deputy", TS: t0, Snapshot: []types.Conn{c}})
	n.Apply(types.RawEvent{Kind: types.KindConnSnapshot, Source: "patrol", TS: t0, Snapshot: []types.Conn{c}})

	// One source going quiet must not close the other's view of the same flow.
	n.Apply(types.RawEvent{Kind: types.KindConnSnapshot, Source: "deputy", TS: t0.Add(time.Second)})
	n.Apply(types.RawEvent{Kind: types.KindConnSnapshot, Source: "deputy", TS: t0.Add(2 * time.Second)})

	if n.Len() != 1 {
		t.Errorf("tracking %d flows, want 1 (patrol's copy should survive)", n.Len())
	}
}

func TestBusDropsOldestWhenSubscriberStalls(t *testing.T) {
	b := NewBus(2)
	ch, cancel := b.Subscribe()
	defer cancel()

	for i := 0; i < 5; i++ {
		b.Publish(Message{Type: "flow", Data: i})
	}

	// The queue is depth 2, so the subscriber should hold the newest messages
	// rather than blocking the publisher or keeping the stalest ones.
	if len(ch) != 2 {
		t.Fatalf("queued %d messages, want 2", len(ch))
	}
	got := (<-ch).Data.(int)
	if got < 3 {
		t.Errorf("kept message %d; expected the newest to survive", got)
	}
}

func TestDirectionClassification(t *testing.T) {
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)

	// This host runs an SSH server and a web server.
	listenSSH := types.Conn{
		Src:       netip.MustParseAddrPort("0.0.0.0:22"),
		Dst:       netip.MustParseAddrPort("0.0.0.0:0"),
		Proto:     types.ProtoTCP,
		State:     "LISTEN",
		Listening: true,
	}
	listenWeb := listenSSH
	listenWeb.Src = netip.MustParseAddrPort("0.0.0.0:8080")

	// Somebody on the internet connected to the SSH server: our local port is
	// one we listen on, so they dialled us.
	inbound := conn("192.168.1.5:22", "203.0.113.9:51234", types.ProtoTCP)
	// We opened a connection to a web server.
	outbound := conn("192.168.1.5:51235", "93.184.216.34:443", types.ProtoTCP)
	// A connection to another machine on the LAN never leaves the network.
	internal := conn("192.168.1.5:51236", "192.168.1.20:445", types.ProtoTCP)

	events := n.Apply(snapshot(t0, listenSSH, listenWeb, inbound, outbound, internal))

	got := map[string]types.Direction{}
	for _, e := range events {
		got[e.Flow.DstIP] = e.Flow.Direction
	}

	if len(events) != 3 {
		t.Fatalf("got %d flows, want 3 (listeners are not flows)", len(events))
	}
	if d := got["203.0.113.9"]; d != types.DirIn {
		t.Errorf("connection to our listening port: direction = %q, want %q", d, types.DirIn)
	}
	if d := got["93.184.216.34"]; d != types.DirOut {
		t.Errorf("connection we opened: direction = %q, want %q", d, types.DirOut)
	}
	if d := got["192.168.1.20"]; d != types.DirInternal {
		t.Errorf("LAN connection: direction = %q, want %q", d, types.DirInternal)
	}
}

func TestDirectionFallbackWithoutListenerInfo(t *testing.T) {
	// A streaming source (Patrol Mode) reports no listeners, so direction falls
	// back to port shape. It must stay conservative: guessing "inbound" wrongly
	// would raise an alarm about traffic the user themselves generated.
	n := NewNormalizer()
	t0 := time.Unix(1700000000, 0)

	toWellKnown := conn("192.168.1.5:51235", "93.184.216.34:443", types.ProtoTCP)
	toOurLowPort := conn("192.168.1.5:443", "203.0.113.9:51234", types.ProtoTCP)
	bothHigh := conn("192.168.1.5:51235", "93.184.216.34:8443", types.ProtoTCP)

	events := n.Apply(snapshot(t0, toWellKnown, toOurLowPort, bothHigh))
	got := map[string]types.Direction{}
	for _, e := range events {
		got[e.Flow.DstIP] = e.Flow.Direction
	}

	if got["93.184.216.34"] != types.DirOut {
		t.Errorf("ephemeral->well-known should read as outbound, got %q", got["93.184.216.34"])
	}
	if got["203.0.113.9"] != types.DirIn {
		t.Errorf("well-known local port from an ephemeral remote should read as inbound, got %q", got["203.0.113.9"])
	}
	// The ambiguous case must not be called inbound.
	n2 := NewNormalizer()
	ev := n2.Apply(snapshot(t0, bothHigh))
	if ev[0].Flow.Direction != types.DirOut {
		t.Errorf("an ambiguous pair should default to outbound, got %q", ev[0].Flow.Direction)
	}
}
