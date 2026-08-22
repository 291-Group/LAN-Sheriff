//go:build windows

package discover

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetIPForwardTab = iphlpapi.NewProc("GetIpForwardTable")

// MIB_IPFORWARDROW, truncated to the fields needed. Addresses are in network
// byte order.
type mibIPForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// The default route is the row whose destination is 0.0.0.0; its next hop is the
// gateway. Where several exist, the lowest metric is the one in use.
func defaultGateway() netip.Addr {
	var size uint32
	ret, _, _ := procGetIPForwardTab.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if windows.Errno(ret) != windows.ERROR_INSUFFICIENT_BUFFER {
		return netip.Addr{}
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIPForwardTab.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if ret != 0 {
		return netip.Addr{}
	}

	count := binary.LittleEndian.Uint32(buf)
	rowSize := unsafe.Sizeof(mibIPForwardRow{})
	if uintptr(size) < unsafe.Sizeof(uint32(0))+uintptr(count)*rowSize {
		return netip.Addr{}
	}

	var (
		best       netip.Addr
		bestMetric uint32 = ^uint32(0)
	)
	for i := uint32(0); i < count; i++ {
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[unsafe.Sizeof(uint32(0))+uintptr(i)*rowSize]))
		if row.ForwardDest != 0 || row.ForwardMetric1 >= bestMetric {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], row.ForwardNextHop)
		addr := netip.AddrFrom4(b)
		if addr.IsValid() && !addr.IsUnspecified() {
			best, bestMetric = addr, row.ForwardMetric1
		}
	}
	return best
}
