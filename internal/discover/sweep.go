package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// The gentle sweep.
//
// Passive discovery only finds devices that talk to this machine. A smart
// television that speaks to the internet and nothing else is invisible to it,
// which is a hole in the one thing the Roster promises.
//
// The sweep closes that without privilege and without raw sockets. Sending any
// datagram to an address on the local segment forces the operating system to
// resolve its hardware address first, and that resolution lands in the
// neighbour table whether or not anything answers. So a single tiny UDP packet
// per address, and then the ordinary neighbour reader picks up the results.
//
// "Gentle" is a constraint, not a description:
//
//   - one packet per address, never a retry storm;
//   - paced, so the sweep is spread over minutes rather than arriving as a burst
//     that looks like a scan to anything watching;
//   - a single port, not a port scan, the point is to make the OS resolve an
//     address, and any port does that equally well;
//   - large subnets are skipped entirely rather than sampled, because a /16
//     sweep is not gentle at any rate.
//
// It is disclosed in the Help view. A tool that promises not to be sneaky should
// not quietly put packets on the wire.

// sweepPort is the discard service. Nothing is expected to answer, and nothing
// needs to: the ARP resolution that precedes the send is the whole point.
const sweepPort = 9

// SweepRate is how many addresses are probed per second.
//
// Ten is slower than any scanner and fast enough to cover a /24 in under half a
// minute. The figure is deliberately conservative: this runs unattended on
// somebody's home network, and the cost of being slow is that the Roster fills
// in a little later.
const SweepRate = 10

// maxSweepHosts bounds a single pass.
//
// A /24 is 254 hosts and is the overwhelmingly common home network. A /22 is
// 1022 and still tolerable. Beyond that the sweep is skipped: a /16 would be
// 65,534 packets, which is not gentle at any pace, and a network that large has
// an administrator with better tools.
const maxSweepHosts = 1024

// SweepTargets lists the addresses a sweep would probe, without sending
// anything.
//
// Separate from the sending so the decision about what to probe can be tested
// without putting packets on a network.
func SweepTargets() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []netip.Addr
	seen := map[netip.Addr]bool{}

	for i := range ifaces {
		iface := ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			hosts := hostsIn(prefix)
			if hosts == 0 || hosts > maxSweepHosts {
				continue
			}
			for addr := range iterateHosts(prefix) {
				if addr == prefix.Addr() || seen[addr] {
					continue
				}
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out, nil
}

// hostsIn counts the usable host addresses in a prefix, or zero if the prefix is
// too large to sweep gently.
//
// The bound lives here rather than in the caller. Enforcing it only in
// SweepTargets left iterateHosts willing to enumerate 65,534 addresses into a
// map for a /16, a bound that one caller remembers is not a bound.
func hostsIn(p netip.Prefix) int {
	bits := p.Addr().BitLen() - p.Bits()
	// A /31 or /32 has no hosts to sweep. Above 20 bits the shift itself is
	// worth avoiding before the size check.
	if bits <= 1 || bits > 20 {
		return 0
	}
	n := (1 << bits) - 2 // minus the network and broadcast addresses
	if n > maxSweepHosts {
		return 0
	}
	return n
}

// iterateHosts yields every host address in a prefix, excluding the network and
// broadcast addresses.
func iterateHosts(p netip.Prefix) map[netip.Addr]struct{} {
	out := map[netip.Addr]struct{}{}
	n := hostsIn(p)
	if n == 0 {
		return out
	}
	addr := p.Masked().Addr().Next() // skip the network address
	for i := 0; i < n; i++ {
		if !p.Contains(addr) {
			break
		}
		out[addr] = struct{}{}
		addr = addr.Next()
	}
	return out
}

// Sweep probes every address on the local segment once, paced.
//
// Errors from individual sends are ignored: an unreachable host is the expected
// case and is exactly as informative as a reachable one, because the neighbour
// table was populated either way.
func Sweep(ctx context.Context) (int, error) {
	targets, err := SweepTargets()
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil
	}

	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return 0, fmt.Errorf("open sweep socket: %w", err)
	}
	defer conn.Close()

	// One byte. There is no protocol here; the send exists to make the operating
	// system resolve a hardware address.
	payload := []byte{0}
	ticker := time.NewTicker(time.Second / SweepRate)
	defer ticker.Stop()

	sent := 0
	for _, addr := range targets {
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		case <-ticker.C:
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.WriteTo(payload, &net.UDPAddr{IP: addr.AsSlice(), Port: sweepPort}); err == nil {
			sent++
		}
	}
	return sent, nil
}
