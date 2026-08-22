package dispatch

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
)

// Telling one failure to connect from another.
//
// # Why this exists
//
// Every failed dial produced one message: "could not reach that address". That
// sentence is true of several completely different faults with completely
// different fixes, and it sent an afternoon down the wrong path more than once.
//
// The two that matter most are opposites, and the operating system already
// distinguishes them:
//
//   - **Refused.** The packet arrived, the far side answered, and nothing was
//     listening on that port. The address is right and the software is not
//     running, or is on another port. Fast, and unambiguous.
//   - **Timed out.** The packet left and nothing came back at all. Somebody is
//     dropping it in silence, which is what a host firewall does: it discards
//     rather than replies, precisely so that a scanner learns nothing. Slow,
//     and the most misleading of the two, because "no answer" feels like "wrong
//     address" and is usually not.
//
// A machine can be up, correct, listening, and reachable at layer 2, and still
// look exactly like a machine that is switched off. Only the timing tells you,
// and only if somebody writes it down.
type Reachability int

const (
	// ReachOther is any failure this file cannot categorize.
	ReachOther Reachability = iota
	// ReachRefused means the connection was actively refused.
	ReachRefused
	// ReachDropped means nothing answered: a timeout, or no route.
	ReachDropped
)

// Classify sorts a dial error into something worth telling a person.
func Classify(err error) Reachability {
	if err == nil {
		return ReachOther
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ReachRefused
	}
	// Timeouts arrive several ways depending on platform and how the deadline
	// was set, so the interface is checked as well as the sentinel values.
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return ReachDropped
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReachDropped
	}
	// No route and unreachable host are the same story for the reader: nothing
	// came back, and the network or a filter is why.
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return ReachDropped
	}
	return ReachOther
}

// TailscalePresent reports whether this machine has a Tailscale interface.
//
// # Why name one product
//
// Because it is the one that caused this, it is extremely common, and the
// setting responsible is on by default for many people. Tailscale's "Block
// incoming connections" discards inbound traffic on **every** interface, not
// only the tailnet, while leaving outbound working perfectly. The result is a
// machine that reaches the internet, reaches its peers, and even reaches its
// own LAN address, while nothing on the network can open a socket to it.
//
// That combination is almost impossible to diagnose from the outside and takes
// minutes to fix once named, so naming it is worth more than a generic
// sentence about firewalls. It is detected rather than assumed, and it is only
// ever mentioned alongside a timeout, never on its own.
//
// Detection is by address range, deliberately. Shelling out to another
// product's binary to read its configuration would be fragile, would need that
// binary on PATH, and would make LAN Sheriff depend on a thing it merely
// coexists with. Every Tailscale node holds an address in 100.64.0.0/10, the
// carrier-grade NAT range Tailscale uses for its tailnet, and reading our own
// interface list costs nothing because Patrol Mode already does it.
func TailscalePresent() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	return tailscaleIn(addrs)
}

// VPNPresent reports the name of a VPN this machine appears to be running, if
// one is recognisable, and whether anything was found at all.
//
// # Why this exists beside the Tailscale check
//
// A tester spent an evening on two machines that paired and then never
// connected, both reporting "Never connected" at each other across one /24. The
// Windows machine was running NordVPN, which puts a TAP adapter in front of the
// default route and, with its kill switch on, discards traffic that does not go
// through the tunnel. Traffic to a machine on the same subnet is exactly that.
//
// This is the same shape as the Tailscale problem: the machine is up, the
// dashboard works, outbound browsing works, and the one port that matters is
// silently dropped. It is worth naming the cause rather than leaving somebody to
// conclude the software is broken.
//
// Matched on interface names because that is what a VPN reliably leaves behind
// and it needs no privilege to read. Deliberately a short list of distinctive
// names: "utun" and "tun0" are not on it, because macOS and Linux use those for
// things that are not VPNs and a false accusation is worse than silence.
func VPNPresent() (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	return vpnIn(names)
}

// vpnIn is the testable half.
func vpnIn(names []string) (string, bool) {
	known := []struct{ match, product string }{
		{"nordlynx", "NordVPN"},
		{"nordvpn", "NordVPN"},
		{"proton", "Proton VPN"},
		{"expressvpn", "ExpressVPN"},
		{"mullvad", "Mullvad"},
		{"surfshark", "Surfshark"},
		{"wireguard", "WireGuard"},
		{"openvpn", "OpenVPN"},
		{"tap-windows", "OpenVPN"},
	}
	for _, n := range names {
		l := strings.ToLower(n)
		for _, k := range known {
			if strings.Contains(l, k.match) {
				return k.product, true
			}
		}
	}
	return "", false
}

// tailscaleIn is the testable half.
func tailscaleIn(addrs []net.Addr) bool {
	// 100.64.0.0/10, from RFC 6598. Tailscale assigns every node an address in
	// it, and it is not otherwise seen on a home network.
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	for _, a := range addrs {
		var ip netip.Addr
		switch v := a.(type) {
		case *net.IPNet:
			ip, _ = netip.AddrFromSlice(v.IP)
		case *net.IPAddr:
			ip, _ = netip.AddrFromSlice(v.IP)
		default:
			continue
		}
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		if ip.Is4() && cgnat.Contains(ip) {
			return true
		}
	}
	return false
}

// OffSubnet reports whether an address is outside every network this machine is
// on, and returns the local networks so the caller can say which they are.
//
// # Why this is worth checking before blaming a firewall
//
// The Dispatch pairs machines on the same network. Nothing enforces that,
// because a routed network with two subnets is a legitimate setup and refusing
// it would be wrong. But the overwhelmingly common case for "it will not
// connect" is that the two machines are not on the same network at all: one on
// Wi-Fi and one on Ethernet behind a different router, a guest network, or an
// address typed from memory that belonged to a different house.
//
// Every one of those produced the same message about firewalls and VPNs, which
// sends somebody to turn off protections that were never the problem. The
// address itself already says so, and it costs nothing to look.
func OffSubnet(target netip.Addr) (locals []netip.Prefix, off bool) {
	if !target.IsValid() || target.IsLoopback() {
		return nil, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() || !addr.IsValid() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			p := netip.PrefixFrom(addr, ones).Masked()
			locals = append(locals, p)
			if p.Contains(target) {
				// On one of our networks: nothing to report.
				return nil, false
			}
		}
	}
	// Only worth saying when we actually know what networks we are on.
	if len(locals) == 0 {
		return nil, false
	}
	return locals, true
}
