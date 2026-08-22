//go:build darwin || freebsd || netbsd || openbsd

// Named _bsd rather than _darwin on purpose. Go derives an implicit build
// constraint from an _<goos> filename suffix and ANDs it with the explicit one,
// so while the constraint above has always listed the BSDs, the filename
// quietly cut this file back to darwin and left FreeBSD with nothing defining
// defaultGateway. The portable release builds FreeBSD, so that was not a
// theoretical gap: goreleaser could not have produced those artifacts. "_bsd"
// means nothing to the toolchain, which leaves the line above in sole charge.

package discover

import (
	"net/netip"

	"golang.org/x/net/route"
)

// On BSD systems the default route comes from the same routing table the
// neighbour reader uses: it is the entry whose destination is 0.0.0.0 and whose
// gateway is a real address rather than a link-layer one.
func defaultGateway() netip.Addr {
	rib, err := route.FetchRIB(afInet, route.RIBTypeRoute, 0)
	if err != nil {
		return netip.Addr{}
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return netip.Addr{}
	}

	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= rtaxGateway {
			continue
		}
		dst, ok := rm.Addrs[rtaxDst].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{0, 0, 0, 0} {
			continue
		}
		gw, ok := rm.Addrs[rtaxGateway].(*route.Inet4Addr)
		if !ok {
			continue
		}
		if addr := netip.AddrFrom4(gw.IP); addr.IsValid() && !addr.IsUnspecified() {
			return addr
		}
	}
	return netip.Addr{}
}
