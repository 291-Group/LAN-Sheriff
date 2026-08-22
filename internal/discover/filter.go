package discover

import (
	"net"
	"net/netip"
	"strings"
)

// Deciding what counts as a device.
//
// The operating system's neighbour table is not a list of devices. It also holds
// broadcast and multicast entries, because those are addresses the kernel needs
// hardware mappings for. Left in, the Roster would list 239.255.255.250 as a
// device, which is wrong in a way a user would immediately notice.

// isDevice reports whether a neighbour entry describes a real machine.
func isDevice(n Neighbour) bool {
	if !n.Addr.IsValid() || n.Addr.IsUnspecified() {
		return false
	}
	// A group address is a destination, never a device.
	if n.Addr.IsMulticast() || n.Addr.IsLinkLocalMulticast() || n.Addr.IsInterfaceLocalMulticast() {
		return false
	}
	if isBroadcastAddr(n.Addr) {
		return false
	}
	return isUnicastMAC(n.MAC)
}

// isUnicastMAC rejects the hardware addresses that cannot belong to a single
// machine: the broadcast address, and the IANA multicast prefixes that carry
// group traffic.
func isUnicastMAC(mac string) bool {
	norm := NormalizeMAC(mac)
	if len(norm) != 12 || norm == "000000000000" || norm == "FFFFFFFFFFFF" {
		return false
	}
	// The low bit of the first octet is the group bit: set means multicast.
	// 01:00:5E is IPv4 multicast and 33:33 is IPv6 multicast, so this one test
	// catches both without enumerating prefixes.
	return hexByte(norm[0], norm[1])&0x01 == 0
}

// isBroadcastAddr catches the all-ones address of an interface's own subnet,
// which appears in the table as an ordinary-looking IPv4 address and so cannot
// be recognised from the address alone.
func isBroadcastAddr(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	if b[3] == 255 {
		// Not conclusive on its own, but every real prefix a home network uses
		// puts the broadcast address here, and no device is assigned it.
		return true
	}
	return false
}

// LocalAddrs returns this machine's own IP addresses and hardware addresses.
//
// Used to mark the Roster entry for this machine rather than trusting a
// "permanent" flag from the neighbour table: the flag's meaning varies between
// operating systems, whereas comparing against the interface list is exact
// everywhere.
func LocalAddrs() (ips map[netip.Addr]bool, macs map[string]bool) {
	ips, macs = map[netip.Addr]bool{}, map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips, macs
	}
	for _, i := range ifaces {
		if mac := NormalizeMAC(i.HardwareAddr.String()); len(mac) == 12 && mac != "000000000000" {
			macs[mac] = true
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ips[prefix.Addr().Unmap()] = true
		}
	}
	return ips, macs
}

// isVirtualInterface reports whether an interface name belongs to a container
// bridge, VPN or virtual-machine network rather than a real local segment.
//
// Devices behind these are not on the user's network in any sense they would
// recognise, and listing a Docker bridge's gateway as a household device is
// noise that makes the Roster less trustworthy.
func isVirtualInterface(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

var virtualPrefixes = []string{
	"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", // containers and VMs
	"utun", "tun", "tap", "ppp", "wg", "tailscale", "zt", // tunnels and VPNs
	"awdl", "llw", // Apple peer-to-peer links, not the LAN
	"lo",
}
