package discover

import "testing"

// The rejected name here is verbatim from an Apple device on the development
// network. Shown in the Roster where a device name belongs, it looked like a bug.
func TestInstanceNameRejectsIdentifiers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Kitchen\\032Speaker._airplay._tcp", "Kitchen Speaker"},
		{"Alex\\039s\\032iPhone._companion-link._tcp", "Alex's iPhone"},
		{"Living\\032Room\\032TV._googlecast._tcp", "Living Room TV"},

		{"f6:c0:74:00:00:0f@fe80::f4c0:74ff:fe52:9ae-supportsRP-24._apple-mobdev2._tcp", ""},
		{"aabbccddeeff._apple-mobdev2._tcp", ""},
		{"_airplay._tcp", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := instanceName(c.in); got != c.want {
			t.Errorf("instanceName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestContainsMAC(t *testing.T) {
	for _, s := range []string{"f6:c0:74:00:00:0f", "prefix-AA-BB-CC-DD-EE-FF-suffix", "30:cd:a7:00:00:03@x"} {
		if !containsMAC(s) {
			t.Errorf("containsMAC(%q) = false, want true", s)
		}
	}
	// A time, a version and an ordinary name must not read as hardware addresses.
	for _, s := range []string{"Kitchen Speaker", "12:30", "1.0.0", "Office-Printer"} {
		if containsMAC(s) {
			t.Errorf("containsMAC(%q) = true, want false", s)
		}
	}
}

// A DNS-SD name embeds the service type, and the enumeration meta-service must
// not be reported as something a device offers.
func TestServiceType(t *testing.T) {
	cases := []struct{ in, want string }{
		{"_airplay._tcp", "_airplay._tcp"},
		{"Kitchen\\032Speaker._raop._udp", "_raop._udp"},
		{"_services._dns-sd._udp", ""},
		{"somehost", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := serviceType(c.in); got != c.want {
			t.Errorf("serviceType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanLabelDecodesEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Kitchen\\032Speaker", "Kitchen Speaker"},
		{"Alex\\039s\\032iPad", "Alex's iPad"},
		{"host\\.name", "host.name"},
		{"plain", "plain"},
		{"  padded  ", "padded"},
	}
	for _, c := range cases {
		if got := cleanLabel(c.in); got != c.want {
			t.Errorf("cleanLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A UUID published under a name key reached the Roster before this was checked.
func TestTXTRejectsIdentifierValues(t *testing.T) {
	var ad Advert
	absorbTXT([]string{
		"n=9ec1570d-f76c-416c-8fb2-3c6a149cce61",
		"md=aabbccddeeff001122334455",
		"ty=Office Printer",
		"model=HP LaserJet 400",
	}, &ad)

	if ad.Name != "Office Printer" {
		t.Errorf("Name = %q, want %q", ad.Name, "Office Printer")
	}
	if ad.Model != "HP LaserJet 400" {
		t.Errorf("Model = %q, want %q", ad.Model, "HP LaserJet 400")
	}
}

func TestIsUUID(t *testing.T) {
	if !isUUID("9ec1570d-f76c-416c-8fb2-3c6a149cce61") {
		t.Error("a canonical UUID was not recognised")
	}
	for _, s := range []string{"Office-Printer", "9ec1570d-f76c", "", "Living Room TV"} {
		if isUUID(s) {
			t.Errorf("isUUID(%q) = true, want false", s)
		}
	}
}
