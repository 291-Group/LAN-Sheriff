//go:build darwin || freebsd || netbsd || openbsd

// Named _bsd rather than _darwin on purpose. Go derives an implicit build
// constraint from an _<goos> filename suffix and ANDs it with the explicit one,
// so while the constraint above has always listed the BSDs, the filename
// quietly cut this file back to darwin and left FreeBSD with nothing defining
// neighbours. The portable release builds FreeBSD, so that was not a
// theoretical gap: goreleaser could not have produced those artifacts. "_bsd"
// means nothing to the toolchain, which leaves the line above in sole charge.

package discover

import (
	"net/netip"
	"time"

	"golang.org/x/net/route"
)

// On BSD systems the neighbour table is exposed through the routing socket
// rather than a file, as route messages carrying a link-layer address.
//
// x/net/route does the message parsing, so this stays pure Go: no cgo, and no
// shelling out to `arp`, which would be fragile and is explicitly ruled out by
// the specification.
func neighbours() ([]Neighbour, error) {
	// RIBTypeRoute with AF_INET returns the routing table, which includes the
	// ARP cache entries as routes with a link-layer gateway.
	rib, err := route.FetchRIB(afInet, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil // unreadable table is not a failure
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil
	}

	names := interfaceNames()
	now := time.Now()
	var out []Neighbour

	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) < 2 {
			continue
		}
		// A neighbour entry is a host route whose gateway is a link-layer
		// address: that pairing is exactly the IP-to-MAC mapping wanted here.
		dst, ok := rm.Addrs[rtaxDst].(*route.Inet4Addr)
		if !ok {
			continue
		}
		link, ok := rm.Addrs[rtaxGateway].(*route.LinkAddr)
		if !ok || len(link.Addr) != 6 {
			continue
		}

		mac := NormalizeMAC(hexMAC(link.Addr))
		if len(mac) != 12 || mac == "000000000000" {
			continue
		}

		out = append(out, Neighbour{
			Addr:      netip.AddrFrom4(dst.IP),
			MAC:       formatMAC(mac),
			Interface: names[link.Index],
			SeenAt:    now,
		})
	}
	return out, nil
}

const (
	afInet = 2 // syscall.AF_INET, named here to avoid the import

	// Positions within a route message's address slice. x/net/route exposes the
	// slice but not the well-known indexes, so they are named here rather than
	// left as bare 0 and 1 at the point of use.
	rtaxDst     = 0
	rtaxGateway = 1
)
