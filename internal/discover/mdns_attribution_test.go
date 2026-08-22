package discover

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildMDNSResponse assembles a response containing the given records.
func buildMDNSResponse(t *testing.T, records []dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true, Authoritative: true},
		Answers: records,
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("name %q: %v", s, err)
	}
	return n
}

func hdr(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{
		Name: mustName(t, name), Type: typ, Class: dnsmessage.ClassINET, TTL: 120,
	}
}

// The bug this file exists for.
//
// DNS-SD lets one host advertise services on behalf of another: a Mac with a
// printer installed republishes that printer's records, and a Bonjour sleep proxy
// answers for sleeping devices. Crediting the packet's sender labelled this
// machine "Samsung M2020 Series" on the development network, which a user would
// read as the product being broken.
//
// The SRV target names the device that actually provides the service, and the A
// record binds that name to an address. Attribution must follow those.
func TestProxiedAdvertGoesToTheRealDevice(t *testing.T) {
	const (
		senderIP  = "192.168.1.24"  // this machine, doing the advertising
		printerIP = "192.168.68.58" // the device the records describe
		instance  = "Samsung M2020 Series (SEC30CDA7C008D0)._ipp._tcp.local."
	)

	data := buildMDNSResponse(t, []dnsmessage.Resource{
		{
			Header: hdr(t, "_ipp._tcp.local.", dnsmessage.TypePTR),
			Body:   &dnsmessage.PTRResource{PTR: mustName(t, instance)},
		},
		{
			Header: hdr(t, instance, dnsmessage.TypeSRV),
			Body: &dnsmessage.SRVResource{
				Port: 631, Target: mustName(t, "PRINTER.local."),
			},
		},
		{
			Header: hdr(t, "PRINTER.local.", dnsmessage.TypeA),
			Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 68, 58}},
		},
	})

	adverts := parseMDNS(multicastPacket{
		From:      netip.MustParseAddrPort(senderIP + ":5353"),
		Interface: "en0",
		Data:      data,
	})
	if len(adverts) == 0 {
		t.Fatal("no adverts parsed")
	}

	var printer *Advert
	for i := range adverts {
		if adverts[i].Addr.Addr().String() == printerIP {
			printer = &adverts[i]
		}
		if adverts[i].Addr.Addr().String() == senderIP && adverts[i].Name != "" {
			t.Errorf("the sender was credited with %q, which belongs to the printer", adverts[i].Name)
		}
	}
	if printer == nil {
		t.Fatalf("nothing was attributed to %s; got %d adverts", printerIP, len(adverts))
	}
	if printer.Name != "Samsung M2020 Series (SEC30CDA7C008D0)" {
		t.Errorf("Name = %q, want the advertised instance name", printer.Name)
	}
	if len(printer.Services) != 1 || printer.Services[0] != "_ipp._tcp" {
		t.Errorf("Services = %v, want [_ipp._tcp]", printer.Services)
	}
	if printer.Hostname != "PRINTER" {
		t.Errorf("Hostname = %q, want %q", printer.Hostname, "PRINTER")
	}
}

// A device advertising only for itself must still be credited to itself, or the
// fix above would break the ordinary case.
func TestSelfAdvertStillGoesToTheSender(t *testing.T) {
	const senderIP = "192.168.68.54"

	data := buildMDNSResponse(t, []dnsmessage.Resource{
		{
			Header: hdr(t, "Living Room._airplay._tcp.local.", dnsmessage.TypeSRV),
			Body: &dnsmessage.SRVResource{
				Port: 7000, Target: mustName(t, "living-room.local."),
			},
		},
		{
			Header: hdr(t, "living-room.local.", dnsmessage.TypeA),
			Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 68, 54}},
		},
	})

	adverts := parseMDNS(multicastPacket{
		From:      netip.MustParseAddrPort(senderIP + ":5353"),
		Interface: "en0",
		Data:      data,
	})

	var found bool
	for _, ad := range adverts {
		if ad.Addr.Addr().String() != senderIP {
			continue
		}
		found = true
		if ad.Name != "Living Room" {
			t.Errorf("Name = %q, want %q", ad.Name, "Living Room")
		}
		if ad.Hostname != "living-room" {
			t.Errorf("Hostname = %q, want %q", ad.Hostname, "living-room")
		}
	}
	if !found {
		t.Errorf("nothing attributed to the sender; got %+v", adverts)
	}
}

// A response to the service-enumeration query lists what the *sender* offers, so
// those do belong to the sender.
func TestEnumerationResponseCreditsTheSender(t *testing.T) {
	const senderIP = "192.168.68.56"

	data := buildMDNSResponse(t, []dnsmessage.Resource{
		{
			Header: hdr(t, "_services._dns-sd._udp.local.", dnsmessage.TypePTR),
			Body:   &dnsmessage.PTRResource{PTR: mustName(t, "_ssh._tcp.local.")},
		},
		{
			Header: hdr(t, "_services._dns-sd._udp.local.", dnsmessage.TypePTR),
			Body:   &dnsmessage.PTRResource{PTR: mustName(t, "_sftp-ssh._tcp.local.")},
		},
	})

	adverts := parseMDNS(multicastPacket{
		From: netip.MustParseAddrPort(senderIP + ":5353"), Interface: "en0", Data: data,
	})
	if len(adverts) != 1 {
		t.Fatalf("got %d adverts, want 1", len(adverts))
	}
	if adverts[0].Addr.Addr().String() != senderIP {
		t.Errorf("attributed to %s, want the sender %s", adverts[0].Addr.Addr(), senderIP)
	}
	if len(adverts[0].Services) != 2 {
		t.Errorf("Services = %v, want both types", adverts[0].Services)
	}
}

// Guards the message parser against a packet that decodes but says nothing.
func TestEmptyMessageProducesNoAdverts(t *testing.T) {
	data := buildMDNSResponse(t, nil)
	if ads := parseMDNS(multicastPacket{
		From: netip.MustParseAddrPort("192.168.68.99:5353"), Data: data,
	}); len(ads) != 0 {
		t.Errorf("got %d adverts from an empty message, want 0", len(ads))
	}
	if ads := parseMDNS(multicastPacket{
		From: netip.MustParseAddrPort("192.168.68.99:5353"), Data: []byte{0x00, 0x01},
	}); len(ads) != 0 {
		t.Errorf("got %d adverts from a malformed message, want 0", len(ads))
	}
}

var _ = time.Now
