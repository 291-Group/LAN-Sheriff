// Package netutil answers the two questions the rest of the app keeps asking:
// "is this address on my own network?" and "who am I?".
package netutil

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// privateRanges are the address blocks that are never routable on the public
// internet, and so never belong on the Watchtower map.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, also Tailscale
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),  // unique local
	netip.MustParsePrefix("fe80::/10"), // link local
	netip.MustParsePrefix("ff00::/8"),  // multicast
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
}

// IsInternal reports whether an address is local to this network rather than a
// destination out on the internet.
func IsInternal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true // unusable; certainly not a map destination
	}
	addr = addr.Unmap()
	for _, p := range privateRanges {
		if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsRoutable reports whether an address is a plausible external destination.
func IsRoutable(addr netip.Addr) bool {
	return addr.IsValid() && !IsInternal(addr)
}

// AddrFromIP converts a net.IP, normalising IPv4-mapped IPv6 to plain IPv4.
//
// Packet capture and the pcap interface list both hand back net.IP, and a
// 4-in-6 address left mapped would be treated as a different endpoint from the
// same address seen over IPv4.
func AddrFromIP(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// Self describes this host.
type Self struct {
	DeviceID string
	Hostname string
	IP       string
	MAC      string
	Subnets  []netip.Prefix
}

var (
	selfOnce sync.Once
	selfVal  Self
)

// Local returns this host's identity, computed once per process.
func Local() Self {
	selfOnce.Do(func() { selfVal = detectSelf() })
	return selfVal
}

func detectSelf() Self {
	s := Self{}
	s.Hostname, _ = os.Hostname()

	ifaces, err := net.Interfaces()
	if err != nil {
		s.DeviceID = deviceID(s.Hostname, "")
		return s
	}

	// Prefer the interface carrying the default route, approximated as the
	// first up, non-loopback interface with a private IPv4 address.
	type cand struct {
		mac  string
		ip   string
		pfx  []netip.Prefix
		rank int
	}
	var cands []cand

	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		c := cand{mac: ifc.HardwareAddr.String(), rank: 100}
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
			ones, _ := ipnet.Mask.Size()
			if p := netip.PrefixFrom(addr, ones); p.IsValid() {
				c.pfx = append(c.pfx, p.Masked())
			}
			if addr.Is4() && IsInternal(addr) && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
				if c.ip == "" {
					c.ip = addr.String()
				}
				// Physical interfaces sort ahead of virtual ones, which keeps
				// Docker and VPN bridges from claiming to be "this machine".
				c.rank = interfaceRank(ifc.Name)
			}
		}
		if len(c.pfx) > 0 {
			cands = append(cands, c)
		}
	}

	sort.SliceStable(cands, func(i, j int) bool { return cands[i].rank < cands[j].rank })
	for _, c := range cands {
		s.Subnets = append(s.Subnets, c.pfx...)
		if s.IP == "" && c.ip != "" {
			s.IP, s.MAC = c.ip, c.mac
		}
	}
	s.DeviceID = deviceID(s.Hostname, s.MAC)
	return s
}

// interfaceRank orders interfaces by how likely they are to be the real one.
// Lower is better.
func interfaceRank(name string) int {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "docker"), strings.HasPrefix(n, "br-"),
		strings.HasPrefix(n, "veth"), strings.HasPrefix(n, "virbr"),
		strings.HasPrefix(n, "vmnet"), strings.HasPrefix(n, "bridge"):
		return 60
	case strings.HasPrefix(n, "tailscale"), strings.HasPrefix(n, "utun"),
		strings.HasPrefix(n, "tun"), strings.HasPrefix(n, "tap"),
		strings.HasPrefix(n, "wg"), strings.HasPrefix(n, "ppp"):
		return 50
	case strings.HasPrefix(n, "en"), strings.HasPrefix(n, "eth"),
		strings.HasPrefix(n, "wl"), strings.HasPrefix(n, "wlan"):
		return 10
	default:
		return 30
	}
}

// deviceID derives a stable identifier for this host. The MAC is hashed rather
// than stored raw so the identifier can be shown in a UI or an export without
// leaking hardware identity.
func deviceID(hostname, mac string) string {
	seed := mac
	if seed == "" {
		seed = hostname
	}
	if seed == "" {
		seed = "unknown-host"
	}
	sum := sha256.Sum256([]byte("lan-sheriff/device/" + seed))
	return "self-" + hex.EncodeToString(sum[:6])
}

// Device renders this host as a Device record.
// Sighting describes this machine in the form the store's identity model takes.
//
// PreferredID carries the ID derived from the local hardware address, because
// the capture sources tag flows with it before the database is open: the record
// discovery converges on has to be the same one those flows point at.
func (s Self) Sighting() types.Sighting {
	return types.Sighting{
		MAC:         s.MAC,
		IP:          s.IP,
		Hostname:    s.Hostname,
		IsSelf:      true,
		Source:      "self",
		SeenAt:      time.Now(),
		PreferredID: s.DeviceID,
	}
}

func (s Self) Device() types.Device {
	now := time.Now()
	name := s.Hostname
	if name == "" {
		name = "This machine"
	}
	return types.Device{
		ID:         s.DeviceID,
		MAC:        s.MAC,
		IP:         s.IP,
		Hostname:   name,
		DeviceType: "this-machine",
		Trust:      types.TrustDeputized, // your own machine starts deputized
		FirstSeen:  now,
		LastSeen:   now,
		Online:     true,
		IsSelf:     true,
	}
}
