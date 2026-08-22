package discover

import (
	"net/netip"
	"testing"
)

// The header in the first case is verbatim from a printer on the development
// network. It is the reason this parser does not simply split on whitespace: the
// product name is three words long, sits before the UPnP marker, and is followed
// by a firmware version and a build date that were previously reported to the
// user as the model.
func TestProductFromServer(t *testing.T) {
	cases := []struct{ header, want string }{
		{"Network Printer Server UPnP/1.0 V3.00.01.23     AUG-16-2018", "Network Printer Server"},
		{"Linux/9.0 UPnP/1.0 Samsung-TV/1.0", "Samsung-TV"},
		{"Linux/4.14 UPnP/1.0 Roku/12.0.0", "Roku"},
		{"UPnP/1.0 DLNADOC/1.50 Platinum/1.0.5.13", "DLNADOC Platinum"},
		{"Windows/10.0 UPnP/1.0", ""},
		{"UPnP/1.0", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := productFromServer(c.header); got != c.want {
			t.Errorf("productFromServer(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestLooksLikeVersionAndDate(t *testing.T) {
	for _, v := range []string{"1.0", "V3.00.01.23", "12.0.0", "v2", "1-0-3"} {
		if !looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"Roku", "Samsung-TV", "Printer", "Platinum"} {
		if looksLikeVersion(v) {
			t.Errorf("looksLikeVersion(%q) = true, want false", v)
		}
	}
	for _, d := range []string{"AUG-16-2018", "JAN-01-2020", "2018-08-16"} {
		if !looksLikeDate(d) {
			t.Errorf("looksLikeDate(%q) = false, want true", d)
		}
	}
	// A product must not be discarded for beginning with a month's letters.
	for _, d := range []string{"Marantz", "Octopus", "Decoder", "Roku"} {
		if looksLikeDate(d) {
			t.Errorf("looksLikeDate(%q) = true, want false", d)
		}
	}
}

// A typeless upnp:rootdevice announcement is common, and the description URL is
// then the only place the device says what it is.
func TestDeviceTypeFromLocation(t *testing.T) {
	cases := []struct{ loc, want string }{
		{"http://192.168.68.58:5200/Printer.xml", "Printer"},
		{"http://192.168.1.1:5000/rootDesc.xml", ""},
		{"http://192.168.1.5:8060/dial/dd.xml", "dd"},
		{"http://192.168.1.9:80/description.xml", ""},
		{"http://192.168.1.9:80/device.xml", ""},
		{"", ""},
		{"::::not a url", ""},
	}
	for _, c := range cases {
		if got := deviceTypeFromLocation(c.loc); got != c.want {
			t.Errorf("deviceTypeFromLocation(%q) = %q, want %q", c.loc, got, c.want)
		}
	}
}

func TestSSDPServiceName(t *testing.T) {
	cases := []struct{ nt, want string }{
		{"urn:schemas-upnp-org:device:MediaRenderer:1", "MediaRenderer"},
		{"urn:schemas-upnp-org:service:AVTransport:1", "AVTransport"},
		{"upnp:rootdevice", ""},
		{"uuid:5f9ec1b3-ed59-1900-4530-00a0deadbeef", ""},
		{"ssdp:all", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ssdpServiceName(c.nt); got != c.want {
			t.Errorf("ssdpServiceName(%q) = %q, want %q", c.nt, got, c.want)
		}
	}
}

// The message below is assembled from the headers a printer on the development
// network actually sends. Pinned as a test because the parser was wrong about it
// twice: it reported the firmware build date as the model, and it found no device
// type at all because the announcement's NT header is the typeless
// "upnp:rootdevice".
func TestParseSSDPRealPrinter(t *testing.T) {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.68.58:5200/Printer.xml\r\n" +
		"SERVER: Network Printer Server UPnP/1.0 V3.00.01.23     AUG-16-2018\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:alive\r\n" +
		"USN: uuid:12345678-1234-1234-1234-0030c1000001::upnp:rootdevice\r\n" +
		"\r\n"

	ad, ok := parseSSDP(multicastPacket{
		From:      mustAddrPort("192.168.68.58:57130"),
		Interface: "en0",
		Data:      []byte(msg),
	})
	if !ok {
		t.Fatal("parseSSDP rejected a valid printer announcement")
	}
	if ad.Model != "Network Printer Server" {
		t.Errorf("Model = %q, want %q", ad.Model, "Network Printer Server")
	}
	if len(ad.Services) != 1 || ad.Services[0] != "Printer" {
		t.Errorf("Services = %v, want [Printer]", ad.Services)
	}
	if ad.Source != "ssdp" || ad.Interface != "en0" {
		t.Errorf("Source = %q, Interface = %q", ad.Source, ad.Interface)
	}
}

// A departing device must not be recorded as present.
func TestParseSSDPIgnoresByebyeAndSearches(t *testing.T) {
	byebye := "NOTIFY * HTTP/1.1\r\nNT: upnp:rootdevice\r\nNTS: ssdp:byebye\r\n" +
		"SERVER: Network Printer Server UPnP/1.0\r\n\r\n"
	if _, ok := parseSSDP(multicastPacket{From: mustAddrPort("192.168.68.58:1900"), Data: []byte(byebye)}); ok {
		t.Error("a byebye announcement was recorded as a present device")
	}

	// An M-SEARCH says what the sender is looking for, not what it is.
	search := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\n\r\n"
	if _, ok := parseSSDP(multicastPacket{From: mustAddrPort("192.168.68.50:61638"), Data: []byte(search)}); ok {
		t.Error("an M-SEARCH request was treated as a device announcement")
	}
}

func mustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}
