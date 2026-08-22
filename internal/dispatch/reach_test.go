package dispatch

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

// Refused and dropped are opposite faults with opposite fixes, and collapsing
// them into one message is what turned a firewall problem into an afternoon of
// checking an address that was correct the whole time.
func TestClassifyTellsRefusedFromDropped(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want Reachability
	}{
		{"refused", syscall.ECONNREFUSED, ReachRefused},
		{"refused, wrapped", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), ReachRefused},
		{"timeout", os.ErrDeadlineExceeded, ReachDropped},
		{"timeout, syscall", syscall.ETIMEDOUT, ReachDropped},
		{"host unreachable", syscall.EHOSTUNREACH, ReachDropped},
		{"net unreachable", syscall.ENETUNREACH, ReachDropped},
		{"anything else", errors.New("tls: bad record"), ReachOther},
		{"nil", nil, ReachOther},
	} {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%s: Classify = %v, want %v", c.name, got, c.want)
		}
	}
}

// net.Error timeouts do not always carry a sentinel, so the interface is
// consulted too.
func TestClassifyUsesTheNetErrorInterface(t *testing.T) {
	var err net.Error = &net.OpError{Op: "dial", Err: &timeoutErr{}}
	if got := Classify(err); got != ReachDropped {
		t.Errorf("Classify(net.Error timeout) = %v, want ReachDropped", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// The detection is by address range rather than by asking Tailscale, so it must
// recognise the tailnet range and nothing else. A false positive here would
// blame Tailscale for somebody else's firewall.
func TestTailscaleDetectedByItsAddressRange(t *testing.T) {
	cidr := func(s string) net.Addr {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return &net.IPNet{IP: n.IP, Mask: n.Mask}
	}
	tailnet := []net.Addr{cidr("192.168.1.20/24"), cidr("100.101.102.103/32")}
	if !tailscaleIn(tailnet) {
		t.Error("a 100.64.0.0/10 address should be recognised as Tailscale")
	}

	ordinary := []net.Addr{cidr("192.168.1.20/24"), cidr("10.0.0.5/8"), cidr("172.16.4.4/12")}
	if tailscaleIn(ordinary) {
		t.Error("an ordinary private network must not be mistaken for Tailscale")
	}

	// 100.63.x and 100.128.x sit either side of the range and are not it.
	for _, s := range []string{"100.63.255.255/32", "100.128.0.1/32"} {
		if tailscaleIn([]net.Addr{cidr(s)}) {
			t.Errorf("%s is outside 100.64.0.0/10 and must not match", s)
		}
	}
}

// A tester's two machines paired and then never connected, across one subnet,
// with NordVPN running on one of them. A kill switch discards anything not going
// through the tunnel, and a machine on your own network is exactly that. The
// symptom is identical to the Tailscale one and equally worth naming.
func TestVPNIsRecognisedByItsInterface(t *testing.T) {
	for _, c := range []struct {
		name    string
		ifaces  []string
		product string
		found   bool
	}{
		{"NordVPN's WireGuard interface", []string{"en0", "nordlynx"}, "NordVPN", true},
		{"NordVPN's TAP adapter on Windows", []string{"Ethernet", "TAP-NordVPN Windows Adapter V9"}, "NordVPN", true},
		{"an OpenVPN adapter", []string{"eth0", "TAP-Windows Adapter V9"}, "OpenVPN", true},
		{"Proton", []string{"en0", "proton0"}, "Proton VPN", true},
		{"an ordinary machine", []string{"lo0", "en0", "en1", "bridge0", "awdl0"}, "", false},
		// Not on the list on purpose: these are not VPNs often enough to accuse.
		{"a plain utun is not accused", []string{"en0", "utun0", "utun1"}, "", false},
		{"nor is a bare tun", []string{"eth0", "tun0"}, "", false},
	} {
		got, found := vpnIn(c.ifaces)
		if found != c.found || got != c.product {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, found, c.product, c.found)
		}
	}
}
