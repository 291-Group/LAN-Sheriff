//go:build patrol

package patrol

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Synthetic packets rather than a capture file: these are deterministic, need no
// privilege, and let each field be varied deliberately.

func buildPacket(t *testing.T, ls ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	// Checksums are deliberately not computed: nothing in the parser verifies
	// them, and computing them requires wiring each transport layer back to its
	// network layer, which would be scaffolding for no benefit.
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	m := pkt.Metadata()
	m.Timestamp = time.Unix(1700000000, 0)
	m.CaptureLength = len(buf.Bytes())
	m.Length = len(buf.Bytes())
	return pkt
}

func eth() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func ip4(src, dst string, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: proto,
		SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst),
	}
}

// ---------- flow assembly ----------

func TestFlowAssemblyCountsBothDirections(t *testing.T) {
	a := newFlowAssembler("self-test")

	// Client opens the connection with a SYN.
	syn := buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true, Seq: 1},
		gopacket.Payload(make([]byte, 20)))
	a.observe(syn)

	// Server answers.
	synack := buildPacket(t, eth(), ip4("93.184.216.34", "192.168.1.5", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 443, DstPort: 51234, SYN: true, ACK: true, Seq: 1, Ack: 2},
		gopacket.Payload(make([]byte, 60)))
	a.observe(synack)

	if got := len(a.flows); got != 1 {
		t.Fatalf("both directions should fold into one flow, got %d", got)
	}

	conns := a.expireAll()
	if len(conns) != 1 {
		t.Fatalf("got %d conns", len(conns))
	}
	c := conns[0]

	// The client initiated, so it must be the source regardless of which packet
	// arrived first.
	if c.Src.Addr().String() != "192.168.1.5" {
		t.Errorf("initiator = %s, want the client that sent the SYN", c.Src.Addr())
	}
	if c.Dst.Port() != 443 {
		t.Errorf("responder port = %d, want 443", c.Dst.Port())
	}
	if c.BytesOut == 0 || c.BytesIn == 0 {
		t.Errorf("both directions should be counted: out=%d in=%d", c.BytesOut, c.BytesIn)
	}
	// The larger packet went server to client.
	if c.BytesIn <= c.BytesOut {
		t.Errorf("expected inbound to exceed outbound: out=%d in=%d", c.BytesOut, c.BytesIn)
	}
}

func TestSynAckIdentifiesTheInitiatorWhenSeenFirst(t *testing.T) {
	// Capture often starts mid-conversation, so the first packet seen may be the
	// server's reply. The SYN+ACK still says who dialled whom.
	a := newFlowAssembler("self-test")
	synack := buildPacket(t, eth(), ip4("93.184.216.34", "192.168.1.5", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 443, DstPort: 51234, SYN: true, ACK: true})
	a.observe(synack)

	conns := a.expireAll()
	if len(conns) != 1 {
		t.Fatalf("got %d conns", len(conns))
	}
	if got := conns[0].Src.Addr().String(); got != "192.168.1.5" {
		t.Errorf("initiator = %s, want the client (a SYN+ACK means the other end dialled)", got)
	}
}

func TestFinClosesAFlowWithoutWaitingForIdle(t *testing.T) {
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true}))
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, FIN: true, ACK: true}))

	// Expiring "now" should release it: teardown was seen, so there is no need
	// to wait out the idle timeout.
	conns := a.expire(time.Unix(1700000000, 0))
	if len(conns) != 1 {
		t.Fatalf("a torn-down flow should be emitted immediately, got %d", len(conns))
	}
	if len(a.flows) != 0 {
		t.Error("the flow should have been removed from the table")
	}
}

func TestNewFlowIsReportedPromptlyButNotExpired(t *testing.T) {
	// A live conversation must appear on the map within a couple of seconds, so
	// the first flush emits a progress report. That is not the same as expiry:
	// the flow stays tracked and keeps accumulating bytes.
	base := time.Unix(1700000000, 0)
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "1.1.1.1", layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 51234, DstPort: 9999}))

	got := a.expire(base.Add(2 * time.Second))
	if len(got) != 1 {
		t.Fatalf("a new flow should be reported on the first flush, got %d", len(got))
	}
	if got[0].State != "ESTABLISHED" {
		t.Errorf("a progress report should be marked ongoing, got state %q", got[0].State)
	}
	if len(a.flows) != 1 {
		t.Error("reporting progress must not remove the flow from the table")
	}

	// Within the report interval, nothing further is emitted.
	if got := a.expire(base.Add(4 * time.Second)); len(got) != 0 {
		t.Errorf("expected no further report inside the interval, got %d", len(got))
	}
}

func TestIdleFlowsExpire(t *testing.T) {
	base := time.Unix(1700000000, 0)
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "1.1.1.1", layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 51234, DstPort: 9999}))
	a.expire(base.Add(time.Second)) // absorb the initial progress report

	if got := a.expire(base.Add(flowIdleTimeout + time.Second)); len(got) != 1 {
		t.Errorf("a flow past the idle timeout should be emitted, got %d", len(got))
	}
	if len(a.flows) != 0 {
		t.Error("an expired flow should be removed from the table")
	}
}

// The trailing-dot normalization is tested directly, because the DNS wire format
// has an implicit root label and a synthetic packet cannot carry one.
func TestDNSNameNormalization(t *testing.T) {
	if got := normalizeDNSName("Telemetry.Example.COM."); got != "telemetry.example.com" {
		t.Errorf("normalizeDNSName = %q", got)
	}
	if got := normalizeDNSName("already.lower"); got != "already.lower" {
		t.Errorf("normalizeDNSName = %q", got)
	}
	if got := normalizeDNSName(""); got != "" {
		t.Errorf("normalizeDNSName(empty) = %q", got)
	}
}

func TestVolumeUsesWireLengthNotSnapshotLength(t *testing.T) {
	// With a small snaplen the captured bytes are far fewer than the real ones.
	// Counting the captured length would silently under-report every volume.
	a := newFlowAssembler("self-test")
	pkt := buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true})
	m := pkt.Metadata()
	m.CaptureLength = 64
	m.Length = 1514 // a full-size frame truncated by the snapshot

	a.observe(pkt)
	conns := a.expireAll()
	if conns[0].BytesOut != 1514 {
		t.Errorf("bytes = %d, want the wire length 1514, not the captured 64", conns[0].BytesOut)
	}
}

func TestFlowTableIsBounded(t *testing.T) {
	a := newFlowAssembler("self-test")
	// Push past the cap and confirm it stops growing.
	for i := 0; i < maxTrackedFlows+500; i++ {
		pkt := buildPacket(t, eth(),
			ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolUDP),
			&layers.UDP{SrcPort: layers.UDPPort(1024 + i%60000), DstPort: layers.UDPPort(i%65535 + 1)})
		a.observe(pkt)
	}
	if len(a.flows) > maxTrackedFlows {
		t.Errorf("flow table grew to %d, past the %d cap", len(a.flows), maxTrackedFlows)
	}
}

func TestNonIPTrafficIsIgnored(t *testing.T) {
	a := newFlowAssembler("self-test")
	arp := buildPacket(t, &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}, &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
		SourceHwAddress: []byte{2, 0, 0, 0, 0, 1}, SourceProtAddress: []byte{192, 168, 1, 5},
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{192, 168, 1, 1},
	})
	a.observe(arp)
	if len(a.flows) != 0 {
		t.Error("ARP is not a flow")
	}
}

// ---------- DNS ----------

func TestParseDNSQuery(t *testing.T) {
	pkt := buildPacket(t, eth(), ip4("192.168.1.5", "1.1.1.1", layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 51234, DstPort: 53},
		&layers.DNS{
			ID: 1, QR: false, QDCount: 1,
			Questions: []layers.DNSQuestion{{
				Name: []byte("Telemetry.Example.COM"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
			}},
		})

	ev := parseDNS(pkt)
	if ev == nil {
		t.Fatal("expected a DNS event")
	}
	// Names are lowercased and the trailing dot dropped, so the same name always
	// aggregates to one row.
	if ev.QName != "telemetry.example.com" {
		t.Errorf("qname = %q", ev.QName)
	}
	if ev.QType != "A" {
		t.Errorf("qtype = %q", ev.QType)
	}
	// A query travels from the asker, so the source is the device.
	if ev.DeviceID != "lan-192.168.1.5" {
		t.Errorf("device = %q, want the asking LAN device", ev.DeviceID)
	}
}

func TestParseDNSResponseAttributesToTheAsker(t *testing.T) {
	// A response travels *to* the asker, so using the source would credit the
	// resolver with every lookup on the network.
	pkt := buildPacket(t, eth(), ip4("1.1.1.1", "192.168.1.5", layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 53, DstPort: 51234},
		&layers.DNS{
			ID: 1, QR: true, QDCount: 1, ANCount: 2,
			Questions: []layers.DNSQuestion{{
				Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
			}},
			Answers: []layers.DNSResourceRecord{
				{Name: []byte("example.com"), Type: layers.DNSTypeCNAME, Class: layers.DNSClassIN,
					CNAME: []byte("Tracker.Ads.EXAMPLE.net.")},
				{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
					IP: net.ParseIP("93.184.216.34")},
			},
		})

	ev := parseDNS(pkt)
	if ev == nil {
		t.Fatal("expected a DNS event")
	}
	if ev.DeviceID != "lan-192.168.1.5" {
		t.Errorf("device = %q, want the asker rather than the resolver", ev.DeviceID)
	}
	if len(ev.Answers) != 2 {
		t.Fatalf("answers = %v", ev.Answers)
	}
	// A CNAME is kept because it is often what reveals an innocuous name
	// resolving into an ad network.
	if ev.Answers[0] != "tracker.ads.example.net" {
		t.Errorf("cname = %q, want it lowercased and dot-stripped", ev.Answers[0])
	}
	if ev.Answers[1] != "93.184.216.34" {
		t.Errorf("address = %q", ev.Answers[1])
	}
}

func TestParseDNSIgnoresNonDNS(t *testing.T) {
	pkt := buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true})
	if ev := parseDNS(pkt); ev != nil {
		t.Errorf("expected no DNS event, got %+v", ev)
	}
}

// ---------- TLS SNI ----------

func TestTLSServerName(t *testing.T) {
	sni := "telemetry.example.com"
	hello := buildClientHello(sni)

	got, ok := tlsServerName(hello)
	if !ok {
		t.Fatal("expected an SNI to be found")
	}
	if got != sni {
		t.Errorf("sni = %q, want %q", got, sni)
	}
}

func TestTLSServerNameRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"too short":       {0x16, 0x03, 0x01},
		"not a handshake": append([]byte{0x17, 0x03, 0x03, 0x00, 0x40}, make([]byte, 64)...),
		"truncated hello": append([]byte{0x16, 0x03, 0x01, 0x00, 0x30, 0x01}, make([]byte, 40)...),
		"random noise":    []byte("this is not TLS at all, not even close to it"),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			// The requirement is that it never panics and never invents a name.
			if got, ok := tlsServerName(payload); ok {
				t.Errorf("found %q in malformed input", got)
			}
		})
	}
}

// buildClientHello assembles a minimal but structurally valid ClientHello
// carrying one server_name extension.
func buildClientHello(sni string) []byte {
	var ext []byte
	ext = append(ext, 0x00, 0x00) // extension type: server_name
	nameLen := len(sni)
	entryLen := 3 + nameLen
	listLen := entryLen
	ext = append(ext, byte((listLen+2)>>8), byte((listLen+2)&0xff)) // extension length
	ext = append(ext, byte(listLen>>8), byte(listLen&0xff))         // server name list length
	ext = append(ext, 0x00)                                         // name type: host_name
	ext = append(ext, byte(nameLen>>8), byte(nameLen&0xff))
	ext = append(ext, []byte(sni)...)

	var hs []byte
	hs = append(hs, 0x03, 0x03)             // client version
	hs = append(hs, make([]byte, 32)...)    // random
	hs = append(hs, 0x00)                   // session id length
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hs = append(hs, 0x01, 0x00)             // compression methods
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)&0xff))
	hs = append(hs, ext...)

	body := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
	return rec
}

// ---------- HTTP ----------

func TestHTTPHost(t *testing.T) {
	req := "GET /pixel.gif HTTP/1.1\r\nUser-Agent: x\r\nHost: Tracker.Example.COM:8080\r\n\r\n"
	got, ok := httpHost([]byte(req))
	if !ok {
		t.Fatal("expected a Host header to be found")
	}
	// Lowercased, and the port stripped, so it matches a DNS name.
	if got != "tracker.example.com" {
		t.Errorf("host = %q", got)
	}
}

func TestHTTPHostRejectsNonRequests(t *testing.T) {
	for name, payload := range map[string]string{
		"a response":     "HTTP/1.1 200 OK\r\nHost: nope\r\n\r\n",
		"binary":         "\x16\x03\x01\x00\x40random",
		"empty":          "",
		"no host header": "GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := httpHost([]byte(payload)); ok {
				t.Errorf("found host %q where there should be none", got)
			}
		})
	}
}

// ---------- device attribution ----------

func TestExternalAddressesGetNoDeviceID(t *testing.T) {
	// A query arriving from outside the network is not one of our devices, and
	// inventing an id for it would put strangers in the Roster.
	if got := deviceIDFor("93.184.216.34"); got != "" {
		t.Errorf("device id for an external address = %q, want empty", got)
	}
	if got := deviceIDFor("not-an-address"); got != "" {
		t.Errorf("device id for garbage = %q, want empty", got)
	}
	if got := deviceIDFor("192.168.1.77"); got != "lan-192.168.1.77" {
		t.Errorf("device id for a LAN address = %q", got)
	}
}

func TestCanonicalKeyIsDirectionIndependent(t *testing.T) {
	k1 := canonicalKey(netip.MustParseAddrPort("192.168.1.5:51234"),
		netip.MustParseAddrPort("93.184.216.34:443"), types.ProtoTCP)
	k2 := canonicalKey(netip.MustParseAddrPort("93.184.216.34:443"),
		netip.MustParseAddrPort("192.168.1.5:51234"), types.ProtoTCP)
	if k1 != k2 {
		t.Error("the same conversation seen from either side must produce one key")
	}
}

// ---------- did the conversation actually come up? ----------

// A refused connection must never be reported as established.
//
// This is a regression test for a real defect. The assembler reported
// ESTABLISHED for any flow still in its table, so a SYN to an address that
// answered nothing counted as a live connection, and the plaintext rule duly
// reported that this machine had "sent VNC traffic unencrypted" to a host that
// had never sent back a single packet.
func TestRefusedConnectionIsNotEstablished(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply gopacket.Packet
	}{
		{name: "no answer at all"},
		{name: "answered with a reset", reply: buildPacket(t,
			eth(), ip4("192.0.2.1", "192.168.1.5", layers.IPProtocolTCP),
			&layers.TCP{SrcPort: 5900, DstPort: 51234, RST: true, ACK: true})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newFlowAssembler("self-test")
			a.observe(buildPacket(t,
				eth(), ip4("192.168.1.5", "192.0.2.1", layers.IPProtocolTCP),
				&layers.TCP{SrcPort: 51234, DstPort: 5900, SYN: true, Seq: 1}))
			if tc.reply != nil {
				a.observe(tc.reply)
			}

			var f *trackedFlow
			for _, tf := range a.flows {
				f = tf
			}
			if f == nil {
				t.Fatal("the flow was not tracked at all")
			}
			if got := a.toConn(f).State; got == "ESTABLISHED" {
				t.Errorf("a connection that was never answered reports %q", got)
			}
		})
	}
}

// The other half of the same defect: a completed conversation was reported with
// no state at all, so ordinary finished traffic (the majority of everything)
// looked as though it had never connected.
func TestCompletedConversationStaysEstablished(t *testing.T) {
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, SYN: true, Seq: 1}))
	a.observe(buildPacket(t, eth(), ip4("93.184.216.34", "192.168.1.5", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 443, DstPort: 51234, SYN: true, ACK: true, Seq: 1, Ack: 2}))
	// Teardown, which is what used to clear the state.
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, FIN: true, ACK: true, Seq: 2, Ack: 2}))

	conns := a.expire(time.Unix(1700000000, 0))
	if len(conns) != 1 {
		t.Fatalf("expected the finished flow to be emitted, got %d", len(conns))
	}
	if conns[0].State != "ESTABLISHED" {
		t.Errorf("a completed conversation reports %q, want ESTABLISHED", conns[0].State)
	}
}

// Capture that begins mid-conversation never sees the handshake, so acceptance
// has to be inferred from the responder speaking at all.
func TestMidConversationCaptureIsEstablished(t *testing.T) {
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "93.184.216.34", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 51234, DstPort: 443, ACK: true, Seq: 900},
		gopacket.Payload(make([]byte, 100))))
	a.observe(buildPacket(t, eth(), ip4("93.184.216.34", "192.168.1.5", layers.IPProtocolTCP),
		&layers.TCP{SrcPort: 443, DstPort: 51234, ACK: true, Seq: 900},
		gopacket.Payload(make([]byte, 100))))

	var f *trackedFlow
	for _, tf := range a.flows {
		f = tf
	}
	if a.toConn(f).State != "ESTABLISHED" {
		t.Error("a conversation joined in progress should count as established")
	}
}

// UDP has no handshake, matching how the socket path treats it.
func TestUDPIsEstablishedWithoutAHandshake(t *testing.T) {
	a := newFlowAssembler("self-test")
	a.observe(buildPacket(t, eth(), ip4("192.168.1.5", "9.9.9.9", layers.IPProtocolUDP),
		&layers.UDP{SrcPort: 51234, DstPort: 53}, gopacket.Payload(make([]byte, 40))))

	var f *trackedFlow
	for _, tf := range a.flows {
		f = tf
	}
	if a.toConn(f).State != "ESTABLISHED" {
		t.Error("UDP has nothing to fail and should count as established")
	}
}
