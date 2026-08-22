package discover

import (
	"net/netip"
	"testing"
)

// The neighbour table contains entries that are not devices, and letting them
// through would put "239.255.255.250" in the Roster. These cases are the ones
// observed on a real home network.
func TestIsDeviceRejectsNonDevices(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		mac  string
		want bool
	}{
		{"router", "192.168.68.1", "CC:BA:BD:00:00:0C", true},
		{"raspberry pi", "192.168.68.52", "DC:A6:32:00:00:0D", true},
		{"randomized but real", "192.168.68.50", "F6:C0:74:00:00:0F", true},
		{"ipv6 device", "fe80::1c2d:3e4f:5a6b:7c8d", "AA:BB:CC:DD:EE:01", true},

		{"subnet broadcast", "192.168.71.255", "FF:FF:FF:FF:FF:FF", false},
		{"ipv4 multicast group", "224.0.0.251", "01:00:5E:00:00:FB", false},
		{"ssdp multicast group", "239.255.255.250", "01:00:5E:7F:FF:FA", false},
		{"ipv6 multicast", "ff02::fb", "33:33:00:00:00:FB", false},
		{"unspecified", "0.0.0.0", "AA:BB:CC:DD:EE:02", false},
		{"incomplete entry", "192.168.68.99", "00:00:00:00:00:00", false},
		{"garbage mac", "192.168.68.98", "not-a-mac", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.ip)
			if err != nil {
				t.Fatalf("bad test address %q: %v", c.ip, err)
			}
			if got := isDevice(Neighbour{Addr: addr, MAC: c.mac}); got != c.want {
				t.Errorf("isDevice(%s, %s) = %v, want %v", c.ip, c.mac, got, c.want)
			}
		})
	}
}

// The group bit is what separates a device address from a group address, and it
// catches both IPv4 and IPv6 multicast without listing prefixes.
func TestIsUnicastMACUsesGroupBit(t *testing.T) {
	for _, mac := range []string{"01:00:5E:00:00:FB", "33:33:00:00:00:01", "FF:FF:FF:FF:FF:FF"} {
		if isUnicastMAC(mac) {
			t.Errorf("isUnicastMAC(%s) = true, want false", mac)
		}
	}
	// A randomized address has the *locally administered* bit set, which is the
	// adjacent bit. Confusing the two would discard every privacy-randomized
	// phone on the network.
	for _, mac := range []string{"F6:C0:74:00:00:0F", "7E:EC:F9:00:00:08", "CC:BA:BD:00:00:0C"} {
		if !isUnicastMAC(mac) {
			t.Errorf("isUnicastMAC(%s) = false, want true", mac)
		}
	}
}

func TestIsVirtualInterface(t *testing.T) {
	virtual := []string{"docker0", "br-1a2b3c", "veth9f8e", "utun4", "tailscale0", "awdl0", "lo0", "vmnet8"}
	real := []string{"en0", "eth0", "wlan0", "Ethernet", "Wi-Fi", "enp3s0"}

	for _, n := range virtual {
		if !isVirtualInterface(n) {
			t.Errorf("isVirtualInterface(%q) = false, want true", n)
		}
	}
	for _, n := range real {
		if isVirtualInterface(n) {
			t.Errorf("isVirtualInterface(%q) = true, want false", n)
		}
	}
}

// This machine must be identifiable, because the Roster shows it differently
// from everything else and the platform "permanent" flags disagreed about which
// entry it was.
func TestLocalAddrsFindsThisMachine(t *testing.T) {
	ips, macs := LocalAddrs()
	if len(ips) == 0 {
		t.Fatal("no local IP addresses found; every machine has at least a loopback")
	}
	if !ips[netip.MustParseAddr("127.0.0.1")] {
		t.Error("loopback not among local addresses")
	}
	// A machine with no hardware address at all is possible in a container, so
	// this is reported rather than asserted.
	t.Logf("local: %d addresses, %d hardware addresses", len(ips), len(macs))
}
