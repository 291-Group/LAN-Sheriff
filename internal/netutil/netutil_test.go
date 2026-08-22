package netutil

import (
	"net/netip"
	"testing"
)

// IsInternal decides what counts as egress. A false negative here would draw a
// private address on a world map; a false positive would hide real outbound
// traffic. Both are worse than most bugs in this codebase, so the table is
// deliberately exhaustive about the edges.
func TestIsInternal(t *testing.T) {
	cases := []struct {
		addr string
		want bool
		why  string
	}{
		{"10.0.0.1", true, "RFC1918 class A"},
		{"10.255.255.255", true, "RFC1918 class A, last"},
		{"172.16.0.1", true, "RFC1918 class B, first"},
		{"172.31.255.255", true, "RFC1918 class B, last"},
		{"172.15.0.1", false, "just below the class B block"},
		{"172.32.0.1", false, "just above the class B block"},
		{"192.168.1.1", true, "RFC1918 class C"},
		{"192.169.0.1", false, "just above the class C block"},
		{"100.64.0.1", true, "CGNAT, also Tailscale"},
		{"100.128.0.1", false, "just above CGNAT"},
		{"127.0.0.1", true, "loopback"},
		{"169.254.1.1", true, "link local"},
		{"224.0.0.1", true, "multicast"},
		{"0.0.0.0", true, "unspecified"},

		{"8.8.8.8", false, "public DNS"},
		{"1.1.1.1", false, "public DNS"},
		{"93.184.216.34", false, "public web host"},

		{"::1", true, "IPv6 loopback"},
		{"fe80::1", true, "IPv6 link local"},
		{"fc00::1", true, "IPv6 unique local"},
		{"fd00::1", true, "IPv6 unique local"},
		{"ff02::1", true, "IPv6 multicast"},
		{"2606:4700::1111", false, "public IPv6"},
		{"2001:4860:4860::8888", false, "public IPv6"},
	}

	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.addr)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := IsInternal(addr); got != c.want {
				t.Errorf("IsInternal(%s) = %v, want %v (%s)", c.addr, got, c.want, c.why)
			}
			if got := IsRoutable(addr); got == c.want {
				t.Errorf("IsRoutable should be the inverse of IsInternal for %s", c.addr)
			}
		})
	}
}

func TestInvalidAddressIsTreatedAsInternal(t *testing.T) {
	// An unusable address must never be drawn on the map, so the safe answer
	// is "internal".
	if !IsInternal(netip.Addr{}) {
		t.Error("the zero address should be treated as internal")
	}
	if IsRoutable(netip.Addr{}) {
		t.Error("the zero address is not routable")
	}
}

func TestIPv4MappedIPv6IsClassifiedByItsIPv4Address(t *testing.T) {
	// ::ffff:192.168.1.1 is a private address wearing an IPv6 costume.
	addr := netip.MustParseAddr("::ffff:192.168.1.1")
	if !IsInternal(addr) {
		t.Error("an IPv4-mapped private address should be internal")
	}
}

func TestInterfaceRankPrefersPhysical(t *testing.T) {
	// Docker bridges and VPN tunnels must not be mistaken for "this machine's"
	// primary interface, or the reported local address is wrong.
	physical := []string{"en0", "eth0", "wlan0", "wlp3s0"}
	virtual := []string{"docker0", "br-abc123", "veth1234", "vmnet1", "bridge100"}
	tunnels := []string{"tailscale0", "utun3", "tun0", "wg0", "ppp0"}

	for _, p := range physical {
		for _, v := range append(append([]string{}, virtual...), tunnels...) {
			if interfaceRank(p) >= interfaceRank(v) {
				t.Errorf("%s (rank %d) should sort ahead of %s (rank %d)",
					p, interfaceRank(p), v, interfaceRank(v))
			}
		}
	}
}

func TestDeviceIDIsStableAndDoesNotLeakTheMAC(t *testing.T) {
	const mac = "a4:83:e7:11:22:33"

	first := deviceID("laptop", mac)
	if first != deviceID("laptop", mac) {
		t.Error("the same inputs must always produce the same id")
	}
	if first == deviceID("laptop", "a4:83:e7:11:22:34") {
		t.Error("a different MAC must produce a different id")
	}
	// The identifier appears in exports and the UI, so the raw hardware
	// address must not be recoverable from it.
	if len(first) > 0 && containsSubstring(first, mac) {
		t.Error("the device id must not contain the MAC address")
	}
	if got := deviceID("", ""); got == "" {
		t.Error("an id should still be produced with no inputs at all")
	}
}

func containsSubstring(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestLocalIsCachedAndUsable(t *testing.T) {
	// Local() reads real interfaces; assert only what must hold on any machine.
	self := Local()
	if self.DeviceID == "" {
		t.Error("this host must always have an identifier")
	}
	if Local().DeviceID != self.DeviceID {
		t.Error("Local() must be stable across calls")
	}

	d := self.Device()
	if !d.IsSelf {
		t.Error("this host's device record should be marked as self")
	}
	if d.Trust != "deputized" {
		t.Errorf("this host should start deputized, got %q", d.Trust)
	}
	if d.Hostname == "" {
		t.Error("a device record should always carry a display name")
	}
}
