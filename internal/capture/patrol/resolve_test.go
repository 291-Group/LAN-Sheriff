//go:build patrol

package patrol

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/pcap"
)

// The Windows case this exists for: the device name is a GUID nobody can type,
// and the name the user has been shown by their operating system is the
// description.
func devs() []pcap.Interface {
	return []pcap.Interface{
		{
			Name:        `\Device\NPF_{D58CFD96-93FA-4DE4-A130-BC7AB369B5B4}`,
			Description: "Realtek Gaming 2.5GbE Family Controller",
			Addresses:   []pcap.InterfaceAddress{{IP: net.ParseIP("192.168.50.115")}},
		},
		{
			Name:        `\Device\NPF_{11111111-2222-3333-4444-555555555555}`,
			Description: "RZ616 Wi-Fi 6E 160MHz",
			Addresses:   []pcap.InterfaceAddress{{IP: net.ParseIP("192.168.1.42")}},
		},
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.5")}}},
	}
}

func TestResolveInterface(t *testing.T) {
	d := devs()
	for _, tc := range []struct {
		name, input, want string
		ok                bool
	}{
		{"exact pcap name", `\Device\NPF_{D58CFD96-93FA-4DE4-A130-BC7AB369B5B4}`, `\Device\NPF_{D58CFD96-93FA-4DE4-A130-BC7AB369B5B4}`, true},
		{"unix style name", "eth0", "eth0", true},
		{"full description", "Realtek Gaming 2.5GbE Family Controller", d[0].Name, true},
		{"description, different case", "realtek gaming 2.5gbe family controller", d[0].Name, true},
		{"unique substring", "Wi-Fi", d[1].Name, true},
		{"by address", "192.168.50.115", d[0].Name, true},
		// The bug report: "Ethernet" is what Windows shows in Settings. It is
		// not the adapter description, so it cannot resolve, and the point is
		// that it fails loudly with a list rather than deep inside pcap.
		{"windows settings label", "Ethernet", "", false},
		{"nonsense", "not-an-interface", "", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveInterface(d, tc.input)
			if ok != tc.ok || got != tc.want {
				t.Errorf("resolveInterface(%q) = %q,%v want %q,%v", tc.input, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// An ambiguous fragment must not be guessed at: capturing the wrong adapter
// produces a dashboard that looks fine and is watching the wrong network.
func TestResolveInterfaceRefusesAmbiguity(t *testing.T) {
	d := []pcap.Interface{
		{Name: "a", Description: "Intel Ethernet Adapter"},
		{Name: "b", Description: "Intel Wireless Adapter"},
	}
	if got, ok := resolveInterface(d, "Intel"); ok {
		t.Errorf("ambiguous %q resolved to %q; it should refuse", "Intel", got)
	}
}

func TestDescribeInterfacesListsWhatToType(t *testing.T) {
	out := describeInterfaces(devs())
	for _, want := range []string{"Realtek", "RZ616", "192.168.50.115"} {
		if !contains(out, want) {
			t.Errorf("listing omits %q:\n%s", want, out)
		}
	}
}

func contains(h, n string) bool {
	return len(h) >= len(n) && (func() bool {
		for i := 0; i+len(n) <= len(h); i++ {
			if h[i:i+len(n)] == n {
				return true
			}
		}
		return false
	})()
}
