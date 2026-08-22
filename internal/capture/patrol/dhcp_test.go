//go:build patrol

package patrol

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildDHCP assembles a DHCP message on the wire, so the parser is exercised
// through real decoding rather than against a hand-made struct.
func buildDHCP(t *testing.T, op layers.DHCPOp, mac string, opts []layers.DHCPOption) gopacket.Packet {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("bad test MAC: %v", err)
	}

	dhcp := &layers.DHCPv4{
		Operation:    op,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x1234,
		ClientIP:     net.IPv4zero,
		YourClientIP: net.IPv4zero,
		ClientHWAddr: hw,
		Options:      opts,
	}
	udp := &layers.UDP{SrcPort: 68, DstPort: 67}
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4zero, DstIP: net.IPv4bcast,
	}
	eth := &layers.Ethernet{
		SrcMAC: hw, DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opt, eth, ip, udp, dhcp); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func opt(t layers.DHCPOpt, data string) layers.DHCPOption {
	return layers.NewDHCPOption(t, []byte(data))
}

// The whole point: a device asking for an address states its own name.
func TestDHCPReportsWhatTheDeviceSaysAboutItself(t *testing.T) {
	pkt := buildDHCP(t, layers.DHCPOpRequest, "aa:bb:cc:dd:ee:01", []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		opt(layers.DHCPOptHostname, "kitchen-tablet"),
		opt(layers.DHCPOptClassID, "android-dhcp-14"),
		layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 15, 26, 28, 51, 58, 59, 43}),
	})

	got := parseDHCP(pkt)
	if got == nil {
		t.Fatal("a DHCP request produced no sighting")
	}
	if got.Hostname != "kitchen-tablet" {
		t.Errorf("Hostname = %q", got.Hostname)
	}
	if got.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q", got.MAC)
	}
	if got.Model != "android-dhcp-14" {
		t.Errorf("Model = %q, want the vendor class", got.Model)
	}
	// The vendor class is the device's own statement and outranks the
	// fingerprint, which for this request list would say Linux.
	if len(got.Services) != 1 || got.Services[0] != "os:Android" {
		t.Errorf("Services = %v, want [os:Android]", got.Services)
	}
	if got.Source != "dhcp" {
		t.Errorf("Source = %q", got.Source)
	}
}

// A server's reply is the server's opinion of the client, not the client's own
// account of itself, and must not be read as one.
func TestDHCPIgnoresServerReplies(t *testing.T) {
	pkt := buildDHCP(t, layers.DHCPOpReply, "aa:bb:cc:dd:ee:02", []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}),
		opt(layers.DHCPOptHostname, "should-be-ignored"),
	})
	if got := parseDHCP(pkt); got != nil {
		t.Errorf("a server reply produced a sighting: %+v", got)
	}
}

// Firmware written in a hurry sends whatever is in the buffer.
func TestDHCPRejectsUnusableText(t *testing.T) {
	pkt := buildDHCP(t, layers.DHCPOpRequest, "aa:bb:cc:dd:ee:03", []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
		layers.NewDHCPOption(layers.DHCPOptHostname, []byte{0x01, 0x02, 0x00, 0x03}),
	})
	got := parseDHCP(pkt)
	if got == nil {
		t.Fatal("expected a sighting from the hardware address alone")
	}
	if got.Hostname != "" {
		t.Errorf("Hostname = %q, want empty for control characters", got.Hostname)
	}
}

// A trailing NUL is normal and must not become part of the name.
func TestDHCPTrimsPadding(t *testing.T) {
	pkt := buildDHCP(t, layers.DHCPOpRequest, "aa:bb:cc:dd:ee:04", []layers.DHCPOption{
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)}),
		layers.NewDHCPOption(layers.DHCPOptHostname, []byte("printer\x00\x00")),
	})
	if got := parseDHCP(pkt); got == nil || got.Hostname != "printer" {
		t.Errorf("Hostname = %q, want %q", got.Hostname, "printer")
	}
}

// The fingerprint is a hint. It must recognise what it claims to and stay quiet
// otherwise, rather than reaching for the nearest match.
func TestFingerprintIsCoarseAndQuiet(t *testing.T) {
	apple := fingerprintOS([]byte{1, 121, 3, 6, 15, 119, 252}, "")
	if apple != "Apple" {
		t.Errorf("Apple request list gave %q", apple)
	}
	if got := fingerprintOS([]byte{99, 98, 97}, ""); got != "" {
		t.Errorf("an unrecognised list gave %q, want empty", got)
	}
	if got := fingerprintOS(nil, ""); got != "" {
		t.Errorf("no request list gave %q, want empty", got)
	}
	// The device's own statement wins over the inference.
	if got := fingerprintOS([]byte{1, 121, 3, 6, 15, 119, 252}, "MSFT 5.0"); got != "Windows" {
		t.Errorf("vendor class did not outrank the fingerprint: %q", got)
	}
}

// A packet that is not DHCP at all must not be mistaken for one.
func TestDHCPIgnoresOtherTraffic(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{192, 168, 1, 2}, DstIP: net.IP{192, 168, 1, 3}}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	if got := parseDHCP(pkt); got != nil {
		t.Errorf("a TCP packet produced a DHCP sighting: %+v", got)
	}
}
