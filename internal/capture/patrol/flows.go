//go:build patrol

package patrol

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Turning packets into flows.
//
// A packet capture is a firehose of individual frames; everything upstream of
// here works in flows. The assembler accumulates packets into 5-tuple records,
// counts bytes in both directions, and emits a record when the conversation has
// been quiet long enough to call it finished.
//
// Unlike Deputy Mode this can measure real volumes, because the bytes are right
// there on the wire. What it cannot do is name the process: a packet carries no
// notion of one. That asymmetry is why the two modes complement each other.

const (
	// flowFlushInterval is how often finished flows are swept out.
	flowFlushInterval = 2 * time.Second

	// flowIdleTimeout is how long a conversation may be silent before it is
	// treated as over. TCP teardown is also honoured, so this mainly governs
	// UDP and connections that vanish without a FIN.
	flowIdleTimeout = 30 * time.Second

	// maxTrackedFlows bounds memory on a busy vantage point. Past this the
	// oldest are expired early rather than growing without limit, because this
	// is expected to run for weeks on a Pi.
	maxTrackedFlows = 65536
)

// flowKey identifies a conversation, direction-independent so that both halves
// accumulate into one record.
type flowKey struct {
	a, b  netip.AddrPort
	proto types.Proto
}

// canonicalKey orders the endpoints so that either direction of the same
// conversation produces one key.
//
// Which end initiated is tracked separately on the flow itself, not derived from
// this ordering: address order is arbitrary, whereas the initiator is a fact
// about the conversation.
func canonicalKey(src, dst netip.AddrPort, proto types.Proto) flowKey {
	if compareAddrPort(src, dst) <= 0 {
		return flowKey{a: src, b: dst, proto: proto}
	}
	return flowKey{a: dst, b: src, proto: proto}
}

func compareAddrPort(x, y netip.AddrPort) int {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c
	}
	switch {
	case x.Port() < y.Port():
		return -1
	case x.Port() > y.Port():
		return 1
	}
	return 0
}

type trackedFlow struct {
	// initiator is the end that opened the conversation, which is what makes
	// direction meaningful. For TCP it is the sender of the SYN; for UDP it is
	// whoever was seen first.
	initiator netip.AddrPort
	responder netip.AddrPort
	proto     types.Proto

	firstSeen time.Time
	lastSeen  time.Time

	// Bytes are counted relative to the initiator: out means initiator to
	// responder.
	bytesOut uint64
	bytesIn  uint64

	// finished marks a TCP conversation whose teardown has been seen, so it can
	// be emitted without waiting out the idle timeout.
	finished bool

	// accepted records that the far end answered, which is the only proof
	// available at the packet level that a TCP conversation actually came up.
	//
	// Deputy Mode reads socket states and is simply told; a capture has to work
	// it out. Any packet back from the responder that is not a reset is
	// sufficient (to send one at all the far end must have accepted) and it
	// stays correct when capture begins in the middle of a long-running
	// conversation, where the handshake was never on the wire to be seen.
	accepted bool

	// lastEmit is when progress was last reported, so a long-lived conversation
	// shows up on the map while it is still running rather than only at the end.
	lastEmit time.Time
}

type flowAssembler struct {
	deviceID string
	flows    map[flowKey]*trackedFlow
}

func newFlowAssembler(deviceID string) *flowAssembler {
	return &flowAssembler{deviceID: deviceID, flows: make(map[flowKey]*trackedFlow, 1024)}
}

// observe folds one packet into the flow table.
func (a *flowAssembler) observe(pkt gopacket.Packet) {
	src, dst, proto, ok := endpointsOf(pkt)
	if !ok {
		return
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	size := uint64(pkt.Metadata().CaptureLength)
	// Length is the wire length; CaptureLength is what the snapshot kept. Volume
	// must be measured from the wire, or a small snaplen would silently
	// under-report every byte count.
	if l := pkt.Metadata().Length; l > 0 {
		size = uint64(l)
	}

	key := canonicalKey(src, dst, proto)
	f, exists := a.flows[key]
	if !exists {
		if len(a.flows) >= maxTrackedFlows {
			a.evictOldest()
		}
		// A SYN without an ACK names the initiator definitively. Failing that,
		// whoever spoke first is the best available answer.
		initiator, responder := src, dst
		if tcp := tcpLayer(pkt); tcp != nil && tcp.SYN && tcp.ACK {
			// This is the response to a SYN, so the *other* end initiated.
			initiator, responder = dst, src
		}
		f = &trackedFlow{
			initiator: initiator,
			responder: responder,
			proto:     proto,
			firstSeen: ts,
			// lastEmit is left zero deliberately: a brand-new conversation is
			// reported on the next flush rather than after a full report
			// interval, so the live map shows a connection within a couple of
			// seconds of it opening instead of appearing dead.
		}
		a.flows[key] = f
	}

	f.lastSeen = ts
	if src == f.initiator {
		f.bytesOut += size
	} else {
		f.bytesIn += size
		// A reset is a refusal, not an answer; everything else means the
		// conversation exists.
		if tcp := tcpLayer(pkt); tcp == nil || !tcp.RST {
			f.accepted = true
		}
	}

	if tcp := tcpLayer(pkt); tcp != nil && (tcp.FIN || tcp.RST) {
		f.finished = true
	}
}

// expire returns flows that are finished or idle, removing them from the table,
// plus progress updates for long-lived conversations.
func (a *flowAssembler) expire(now time.Time) []types.Conn {
	var out []types.Conn
	for key, f := range a.flows {
		idle := now.Sub(f.lastSeen)
		switch {
		case f.finished || idle > flowIdleTimeout:
			out = append(out, a.toConn(f))
			delete(a.flows, key)

		case now.Sub(f.lastEmit) >= flowReportInterval:
			// Report progress so the map shows an ongoing transfer rather than
			// nothing until it completes.
			f.lastEmit = now
			out = append(out, a.toConn(f))
		}
	}
	return out
}

// flowReportInterval is how often an ongoing conversation reports progress.
const flowReportInterval = 5 * time.Second

// expireAll flushes everything, for shutdown.
func (a *flowAssembler) expireAll() []types.Conn {
	out := make([]types.Conn, 0, len(a.flows))
	for key, f := range a.flows {
		out = append(out, a.toConn(f))
		delete(a.flows, key)
	}
	return out
}

// evictOldest drops the least recently active flow, to bound memory.
func (a *flowAssembler) evictOldest() {
	var oldestKey flowKey
	var oldest time.Time
	first := true
	for k, f := range a.flows {
		if first || f.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, f.lastSeen, false
		}
	}
	if !first {
		delete(a.flows, oldestKey)
	}
}

func (a *flowAssembler) toConn(f *trackedFlow) types.Conn {
	c := types.Conn{
		Src:      f.initiator,
		Dst:      f.responder,
		Proto:    f.proto,
		BytesOut: f.bytesOut,
		BytesIn:  f.bytesIn,
	}

	// **Whether a conversation came up, not whether it is still open.**
	//
	// This used to report ESTABLISHED for any flow still in the table and no
	// state at all for one that had finished, which is wrong in both
	// directions: a connection that was refused counted as established for as
	// long as it sat here, while every ordinary completed conversation, the
	// majority of all traffic, was recorded as never having connected.
	//
	// Six suspicion rules filter on established, so both halves mattered. The
	// visible one was a report that this machine had "sent VNC traffic
	// unencrypted" to an address that never answered a packet: the connection
	// was refused, so nothing was ever sent.
	//
	// UDP has no handshake and so has nothing to fail, matching how the socket
	// path treats it.
	if f.proto == types.ProtoUDP || f.accepted {
		c.State = "ESTABLISHED"
	}

	// Attribute the flow to a device. Only traffic originating on this host is
	// tagged with our device ID; anything else belongs to a LAN device, which
	// M4's discovery will name. Guessing here would put another device's
	// traffic under this machine's name.
	if netutil.IsInternal(f.initiator.Addr()) {
		self := netutil.Local()
		if self.IP != "" && f.initiator.Addr().String() == self.IP {
			c.DeviceID = a.deviceID
		} else if !f.initiator.Addr().IsUnspecified() {
			// A stable placeholder keyed on the address, held only until
			// discovery ties that address to a device, see
			// adoptPlaceholderFlows, which completes the handover.
			//
			// **0.0.0.0 is excluded.** A DHCP client asking for its first lease
			// has no address yet and sends from the unspecified one, which is
			// not a device and never becomes one: it would sit in the flow table
			// as `lan-0.0.0.0` forever, matching no address discovery could ever
			// learn.
			c.DeviceID = "lan-" + f.initiator.Addr().String()
		}
	}
	return c
}

// endpointsOf extracts the 5-tuple from a packet, reporting false for anything
// that is not IP-carried TCP or UDP.
func endpointsOf(pkt gopacket.Packet) (src, dst netip.AddrPort, proto types.Proto, ok bool) {
	var srcAddr, dstAddr netip.Addr

	switch l := pkt.Layer(layers.LayerTypeIPv4); {
	case l != nil:
		ip, _ := l.(*layers.IPv4)
		srcAddr, ok = netutil.AddrFromIP(ip.SrcIP)
		if !ok {
			return src, dst, proto, false
		}
		dstAddr, ok = netutil.AddrFromIP(ip.DstIP)
		if !ok {
			return src, dst, proto, false
		}
	default:
		l6 := pkt.Layer(layers.LayerTypeIPv6)
		if l6 == nil {
			return src, dst, proto, false
		}
		ip6, _ := l6.(*layers.IPv6)
		srcAddr, ok = netutil.AddrFromIP(ip6.SrcIP)
		if !ok {
			return src, dst, proto, false
		}
		dstAddr, ok = netutil.AddrFromIP(ip6.DstIP)
		if !ok {
			return src, dst, proto, false
		}
	}

	if tcp := tcpLayer(pkt); tcp != nil {
		return netip.AddrPortFrom(srcAddr, uint16(tcp.SrcPort)),
			netip.AddrPortFrom(dstAddr, uint16(tcp.DstPort)), types.ProtoTCP, true
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		udp, _ := l.(*layers.UDP)
		return netip.AddrPortFrom(srcAddr, uint16(udp.SrcPort)),
			netip.AddrPortFrom(dstAddr, uint16(udp.DstPort)), types.ProtoUDP, true
	}
	return src, dst, proto, false
}

func tcpLayer(pkt gopacket.Packet) *layers.TCP {
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp, _ := l.(*layers.TCP)
		return tcp
	}
	return nil
}
