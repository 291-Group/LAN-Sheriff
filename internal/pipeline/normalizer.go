// Package pipeline turns raw capture observations into the flow events the
// rest of the application consumes, so that nothing downstream needs to know
// whether an observation came from a socket table or a packet capture.
package pipeline

import (
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Phase is what happened to a flow.
type Phase string

const (
	PhaseOpen   Phase = "open"
	PhaseUpdate Phase = "update"
	PhaseClose  Phase = "close"
)

// FlowEvent is a change to one tracked flow.
type FlowEvent struct {
	Phase Phase
	Flow  types.Flow
}

// DefaultGraceRounds is how many consecutive samples a flow must be absent from
// before it is called closed. Polling sources race with short-lived sockets, and
// UDP "connections" in particular flicker in and out of the table; requiring two
// misses stops one unlucky sample from closing and reopening a live flow.
const DefaultGraceRounds = 2

// Normalizer converts capture events into flow events. Polling sources deliver
// complete snapshots and the normalizer diffs consecutive ones; streaming
// sources deliver deltas, which are applied directly.
//
// It is not safe for concurrent use: drive it from a single goroutine.
type Normalizer struct {
	// GraceRounds is the close delay described above. Zero means the default.
	GraceRounds int
	// Now is the clock, overridable for tests.
	Now func() time.Time

	tracked map[trackKey]*tracked
	nextID  int64

	// listening is the set of local ports this host accepts connections on,
	// rebuilt from each snapshot. It is what makes an inbound connection
	// recognizable: a connection whose *local* port is one we listen on was
	// opened by the other end.
	listening map[listenKey]bool
}

type listenKey struct {
	proto types.Proto
	port  uint16
}

type trackKey struct {
	source string
	flow   types.FlowKey
}

type tracked struct {
	flow   types.Flow
	missed int
	seen   bool
}

// NewNormalizer returns a ready normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		GraceRounds: DefaultGraceRounds,
		Now:         time.Now,
		tracked:     make(map[trackKey]*tracked),
		listening:   make(map[listenKey]bool),
	}
}

func (n *Normalizer) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

func (n *Normalizer) graceRounds() int {
	if n.GraceRounds <= 0 {
		return DefaultGraceRounds
	}
	return n.GraceRounds
}

// Apply feeds one raw event in and returns the flow events it produced.
func (n *Normalizer) Apply(ev types.RawEvent) []FlowEvent {
	ts := ev.TS
	if ts.IsZero() {
		ts = n.now()
	}
	switch ev.Kind {
	case types.KindConnSnapshot:
		return n.applySnapshot(ev.Source, ts, ev.Snapshot)
	case types.KindConnDelta:
		if ev.Conn == nil {
			return nil
		}
		if e, ok := n.observe(ev.Source, ts, *ev.Conn); ok {
			return []FlowEvent{e}
		}
	}
	return nil
}

func (n *Normalizer) applySnapshot(source string, ts time.Time, conns []types.Conn) []FlowEvent {
	// Rebuild the listening set first: direction classification below depends
	// on knowing which local ports are servers.
	n.listening = make(map[listenKey]bool, len(n.listening))
	for _, c := range conns {
		if c.Listening {
			n.listening[listenKey{c.Proto, c.Src.Port()}] = true
		}
	}

	for k, t := range n.tracked {
		if k.source == source {
			t.seen = false
		}
	}

	out := make([]FlowEvent, 0, len(conns))
	for _, c := range conns {
		if e, ok := n.observe(source, ts, c); ok {
			out = append(out, e)
		}
	}

	// Anything this source used to see and no longer does is a candidate for
	// closing, once it has been absent long enough.
	for k, t := range n.tracked {
		if k.source != source || t.seen {
			continue
		}
		t.missed++
		if t.missed < n.graceRounds() {
			continue
		}
		t.flow.Active = false
		out = append(out, FlowEvent{Phase: PhaseClose, Flow: t.flow})
		delete(n.tracked, k)
	}
	return out
}

// observe records one connection sighting, returning the resulting event. It
// reports false for observations that are not flows at all.
func (n *Normalizer) observe(source string, ts time.Time, c types.Conn) (FlowEvent, bool) {
	if !isFlow(c) {
		return FlowEvent{}, false
	}
	k := trackKey{source: source, flow: c.Key()}

	t, existing := n.tracked[k]
	if !existing {
		n.nextID++
		t = &tracked{flow: types.Flow{
			ID:        n.nextID,
			Key:       c.Key(),
			TSStart:   ts,
			TSLast:    ts,
			DeviceID:  c.DeviceID,
			Process:   c.Process,
			PID:       c.PID,
			SrcIP:     c.Src.Addr().String(),
			SrcPort:   c.Src.Port(),
			DstIP:     c.Dst.Addr().String(),
			DstPort:   c.Dst.Port(),
			Proto:     c.Proto,
			BytesOut:  c.BytesOut,
			BytesIn:   c.BytesIn,
			Direction: n.direction(c),
			Active:    true,
			// A connection counts as established once the transport says data
			// could flow. Sources that expose no state leave this false, which
			// is the conservative reading.
			Established: isEstablished(c.State),
		}}
		n.tracked[k] = t
		t.seen = true
		return FlowEvent{Phase: PhaseOpen, Flow: t.flow}, true
	}

	t.seen = true
	t.missed = 0
	t.flow.TSLast = ts
	t.flow.Active = true
	// Streaming sources report per-observation byte deltas; polling sources
	// report cumulative counters. Taking the max of the two interpretations
	// keeps both honest without the normalizer needing to know which is which.
	if c.BytesOut > t.flow.BytesOut {
		t.flow.BytesOut = c.BytesOut
	}
	if c.BytesIn > t.flow.BytesIn {
		t.flow.BytesIn = c.BytesIn
	}
	// A late-arriving process attribution is worth keeping: the socket can show
	// up in the table a moment before we manage to map it to its owner.
	if t.flow.Process == "" && c.Process != "" {
		t.flow.Process = c.Process
		t.flow.PID = c.PID
	}
	return FlowEvent{Phase: PhaseUpdate, Flow: t.flow}, true
}

// direction works out who opened a connection.
//
// The reliable signal is the listening set: if the local end of a connection is
// a port we accept on, the other end dialled us. Without that (a streaming
// source that never reports listeners) it falls back to comparing ports, since
// the initiator almost always uses a high ephemeral port and the server a lower
// well-known one. The fallback is a heuristic and is deliberately conservative:
// when neither side looks like a server, the connection is treated as outbound,
// because over-reporting inbound connections would cry wolf.
func (n *Normalizer) direction(c types.Conn) types.Direction {
	if netutil.IsInternal(c.Dst.Addr()) {
		return types.DirInternal
	}
	if n.listening[listenKey{c.Proto, c.Src.Port()}] {
		return types.DirIn
	}
	if len(n.listening) == 0 {
		const ephemeralFloor = 32768
		if c.Src.Port() < 1024 && c.Dst.Port() >= ephemeralFloor {
			return types.DirIn
		}
	}
	return types.DirOut
}

// isFlow rejects observations that are not connections between two endpoints:
// listening sockets, and unbound or half-formed entries.
func isFlow(c types.Conn) bool {
	// A listening socket is a standing offer, not a connection.
	if c.Listening {
		return false
	}
	if !c.Src.IsValid() || !c.Dst.IsValid() {
		return false
	}
	if c.Dst.Port() == 0 {
		return false
	}
	return !c.Dst.Addr().IsUnspecified()
}

// Active returns every flow currently believed open.
func (n *Normalizer) Active() []types.Flow {
	out := make([]types.Flow, 0, len(n.tracked))
	for _, t := range n.tracked {
		out = append(out, t.flow)
	}
	return out
}

// Len reports how many flows are being tracked.
func (n *Normalizer) Len() int { return len(n.tracked) }

// isEstablished reports whether a transport state means the connection actually
// came up.
//
// Everything from ESTABLISHED onward did: a socket in CLOSE_WAIT or TIME_WAIT
// completed a handshake and is now winding down. SYN_SENT and SYN_RECEIVED did
// not, and neither did LISTEN or CLOSED. UDP has no handshake, so a UDP flow is
// treated as established, there is nothing to fail.
func isEstablished(state string) bool {
	switch state {
	case "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "CLOSING", "LAST_ACK", "TIME_WAIT":
		return true
	case "", "LISTEN", "CLOSED", "SYN_SENT", "SYN_RECEIVED":
		return false
	}
	return false
}
