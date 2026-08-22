//go:build windows

package discover

import (
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows neighbour table comes from the IP Helper API.
//
// GetIpNetTable returns the ARP cache directly, and needs no privilege. As with
// the socket tables in the Deputy Mode sampler, this goes through x/sys/windows
// rather than cgo, so the Windows build stays cross-compilable from any
// machine.
var (
	iphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIPNetTab = iphlpapi.NewProc("GetIpNetTable")
)

// MIB_IPNETROW. The address is in network byte order; the hardware address is a
// fixed 8-byte field of which PhysAddrLen bytes are meaningful.
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

// ARP entry types from iprtrmib.h. Type 2 is an incomplete entry, where Windows
// has an address but no answer yet, and 1 is "other".
const (
	ipNetRowTypeInvalid    = 1
	ipNetRowTypeIncomplete = 2
)

func neighbours() ([]Neighbour, error) {
	// Ask for the required size first: the table is variable-length and the
	// documented way to size it is to call with a buffer that is too small.
	var size uint32
	ret, _, _ := procGetIPNetTab.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if windows.Errno(ret) != windows.ERROR_INSUFFICIENT_BUFFER {
		// An empty table is reported as success with size zero, which is not a
		// failure: this machine simply has no neighbours cached yet.
		return nil, nil
	}

	buf := make([]byte, size)
	ret, _, _ = procGetIPNetTab.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if ret != 0 {
		return nil, windows.Errno(ret)
	}

	// MIB_IPNETTABLE is a count followed by that many rows.
	count := binary.LittleEndian.Uint32(buf)
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	if uintptr(size) < unsafe.Sizeof(uint32(0))+uintptr(count)*rowSize {
		return nil, nil // truncated buffer; report nothing rather than read past it
	}

	names := interfaceNames()
	now := time.Now()
	out := make([]Neighbour, 0, count)

	for i := uint32(0); i < count; i++ {
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[unsafe.Sizeof(uint32(0))+uintptr(i)*rowSize]))
		if row.Type == ipNetRowTypeIncomplete || row.Type == ipNetRowTypeInvalid {
			continue
		}
		if row.PhysAddrLen != 6 {
			// Anything other than an Ethernet address is not a device this
			// product has anything useful to say about.
			continue
		}

		var ip [4]byte
		binary.LittleEndian.PutUint32(ip[:], row.Addr)
		mac := NormalizeMAC(hexMAC(row.PhysAddr[:6]))
		if len(mac) != 12 {
			continue
		}

		out = append(out, Neighbour{
			Addr:      netip.AddrFrom4(ip),
			MAC:       formatMAC(mac),
			Interface: names[int(row.Index)],
			SeenAt:    now,
		})
	}
	return out, nil
}
