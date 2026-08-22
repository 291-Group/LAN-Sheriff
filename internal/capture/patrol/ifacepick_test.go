//go:build patrol

package patrol

import "testing"

// The device name is a Unix idea. On Windows every device is \Device\NPF_{GUID},
// so a picker that reads only the name scored every adapter identically and let
// enumeration order decide. A tester's Windows machine landed on an adapter that
// carried no DNS at all, and the log named only the GUID, so there was nothing
// to notice.
//
// The descriptions below are the real strings Windows reports.
func TestInterfacePenaltyReadsWindowsDescriptions(t *testing.T) {
	const guid = `\Device\NPF_{2E1B0F3A-4C7D-4A1E-9F62-8B3D5C7A1E44}`

	for _, c := range []struct {
		desc    string
		wantMax int // penalty must be at or below this
		wantMin int // and at or above this
		why     string
	}{
		// Real hardware, which must win.
		{"Intel(R) Wi-Fi 6E AX211 160MHz", 0, 0, "a wireless NIC"},
		{"Realtek PCIe GbE Family Controller", 0, 0, "a wired NIC"},
		{"Intel(R) Ethernet Connection I219-V", 0, 0, "a wired NIC"},

		// Virtual switches, which must lose. The Hyper-V one is the case that
		// matters: its description contains "Ethernet".
		{"Hyper-V Virtual Ethernet Adapter", 18, 18, "a virtual switch"},
		{"VMware Virtual Ethernet Adapter for VMnet8", 18, 18, "a virtual switch"},
		{"VirtualBox Host-Only Ethernet Adapter", 18, 18, "a host-only adapter"},
		{"Microsoft Wi-Fi Direct Virtual Adapter", 18, 18, "not a real network"},
		{"Npcap Loopback Adapter", 18, 18, "loopback"},
		{"WAN Miniport (IP)", 18, 18, "not a real adapter"},
		{"Bluetooth Device (Personal Area Network)", 18, 18, "not the network"},

		// Tunnels: real traffic, wrong vantage point.
		{"TAP-Windows Adapter V9", 12, 12, "a VPN tunnel"},
		{"Tailscale Tunnel", 12, 12, "a tunnel"},
		{"WireGuard Tunnel", 12, 12, "a tunnel"},
	} {
		got := interfacePenalty(guid, c.desc)
		if got < c.wantMin || got > c.wantMax {
			t.Errorf("interfacePenalty(GUID, %q) = %d, want %d..%d (%s)",
				c.desc, got, c.wantMin, c.wantMax, c.why)
		}
	}
}

// A real NIC must outscore a virtual switch even when the virtual one is
// enumerated first, which is what actually decided it before.
func TestPhysicalAdapterBeatsVirtualSwitchRegardlessOfOrder(t *testing.T) {
	const guid = `\Device\NPF_{0}`
	virtual := interfacePenalty(guid, "Hyper-V Virtual Ethernet Adapter")
	physical := interfacePenalty(guid, "Intel(R) Wi-Fi 6E AX211 160MHz")
	if !(physical < virtual) {
		t.Fatalf("physical penalty %d is not better than virtual %d; enumeration order still decides",
			physical, virtual)
	}
}

// Unix naming must keep working exactly as before.
func TestUnixNamesStillDecideWhenThereIsNoDescription(t *testing.T) {
	for _, c := range []struct {
		name string
		want int
	}{
		{"en0", 0}, {"eth0", 0}, {"wlan0", 0},
		{"docker0", 18}, {"vmnet1", 18}, {"br-1a2b3c", 18},
		{"utun3", 12}, {"tailscale0", 12},
		{"weird9", 6},
	} {
		if got := interfacePenalty(c.name, ""); got != c.want {
			t.Errorf("interfacePenalty(%q, \"\") = %d, want %d", c.name, got, c.want)
		}
	}
}
