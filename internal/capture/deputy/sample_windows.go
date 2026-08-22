//go:build windows

package deputy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// iphlpapiSampler reads the socket tables through the IP Helper API.
//
// GetExtendedTcpTable and GetExtendedUdpTable, asked for the *_OWNER_PID table
// classes, return the connection list already paired with the PID that owns
// each entry, so unlike Linux there is no inode-to-process mapping to do.
//
// This is pure Go via x/sys/windows: no cgo, so the Windows build stays
// cross-compilable from any machine.
type iphlpapiSampler struct {
	procs map[uint32]procInfo
}

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTab = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTab = iphlpapi.NewProc("GetExtendedUdpTable")
)

// Table classes from iprtrmib.h.
const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

// MIB_TCPROW_OWNER_PID. Addresses and ports are in network byte order.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// MIB_TCP6ROW_OWNER_PID.
type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// MIB_UDPROW_OWNER_PID.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// MIB_UDP6ROW_OWNER_PID.
type mibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func newSampler() (sampler, error) {
	if err := iphlpapi.Load(); err != nil {
		return nil, fmt.Errorf("load iphlpapi.dll: %w", err)
	}
	if err := procGetExtendedTCPTab.Find(); err != nil {
		return nil, fmt.Errorf("GetExtendedTcpTable unavailable: %w", err)
	}
	return &iphlpapiSampler{procs: make(map[uint32]procInfo)}, nil
}

// byteCounts reports false: these tables carry no cumulative byte counters.
func (s *iphlpapiSampler) byteCounts() bool { return false }

func (s *iphlpapiSampler) close() error { return nil }

func (s *iphlpapiSampler) sample() ([]types.Conn, error) {
	var conns []types.Conn
	live := make(map[uint32]procInfo, len(s.procs))

	// A failure on one table should not lose the others: a machine with IPv6
	// disabled still has a perfectly good IPv4 table.
	var lastErr error
	for _, read := range []func() ([]types.Conn, error){
		s.tcp4, s.tcp6, s.udp4, s.udp6,
	} {
		got, err := read()
		if err != nil {
			lastErr = err
			continue
		}
		conns = append(conns, got...)
	}
	if len(conns) == 0 && lastErr != nil {
		return nil, lastErr
	}

	for i := range conns {
		pid := uint32(conns[i].PID)
		info, ok := live[pid]
		if !ok {
			if cached, hit := s.procs[pid]; hit {
				info = cached
			} else {
				info = processInfo(pid)
			}
			live[pid] = info
		}
		conns[i].Process = info.name
		conns[i].ProcessPath = info.path
	}
	s.procs = live
	return conns, nil
}

// table calls one of the GetExtended*Table functions, sizing the buffer as the
// API asks. The size is re-queried on each call because the table can grow
// between the sizing call and the fetch.
func table(proc *windows.LazyProc, family uint32, class uint32) ([]byte, error) {
	var size uint32
	for attempt := 0; attempt < 4; attempt++ {
		var buf []byte
		var ptr unsafe.Pointer
		if size > 0 {
			buf = make([]byte, size)
			ptr = unsafe.Pointer(&buf[0])
		}
		ret, _, _ := proc.Call(
			uintptr(ptr),
			uintptr(unsafe.Pointer(&size)),
			0, // unordered: we do not care about sort order
			uintptr(family),
			uintptr(class),
			0,
		)
		switch ret {
		case 0:
			return buf, nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			continue // size now holds what is needed; go round again
		default:
			return nil, fmt.Errorf("table query failed: %w", windows.Errno(ret))
		}
	}
	return nil, fmt.Errorf("table kept growing between sizing and fetch")
}

// rows reinterprets the buffer returned by the API, which is a DWORD count
// followed by a packed array of fixed-size records.
func rows[T any](buf []byte) []T {
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	if n == 0 {
		return nil
	}
	var zero T
	stride := int(unsafe.Sizeof(zero))
	// The array starts after the count, aligned to the record's alignment.
	const headerSize = 4
	if len(buf) < headerSize+int(n)*stride {
		// Trust the buffer over the count rather than reading past the end.
		n = uint32((len(buf) - headerSize) / stride)
	}
	if n == 0 {
		return nil
	}
	return unsafe.Slice((*T)(unsafe.Pointer(&buf[headerSize])), int(n))
}

func (s *iphlpapiSampler) tcp4() ([]types.Conn, error) {
	buf, err := table(procGetExtendedTCPTab, windows.AF_INET, tcpTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	var out []types.Conn
	for _, r := range rows[mibTCPRowOwnerPID](buf) {
		state := windowsTCPState(r.State)
		out = append(out, types.Conn{
			Src:       netip.AddrPortFrom(addr4(r.LocalAddr), port(r.LocalPort)),
			Dst:       netip.AddrPortFrom(addr4(r.RemoteAddr), port(r.RemotePort)),
			Proto:     types.ProtoTCP,
			State:     state,
			Listening: state == "LISTEN",
			PID:       int32(r.OwningPID),
		})
	}
	return out, nil
}

func (s *iphlpapiSampler) tcp6() ([]types.Conn, error) {
	buf, err := table(procGetExtendedTCPTab, windows.AF_INET6, tcpTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	var out []types.Conn
	for _, r := range rows[mibTCP6RowOwnerPID](buf) {
		state := windowsTCPState(r.State)
		out = append(out, types.Conn{
			Src:       netip.AddrPortFrom(addr16(r.LocalAddr), port(r.LocalPort)),
			Dst:       netip.AddrPortFrom(addr16(r.RemoteAddr), port(r.RemotePort)),
			Proto:     types.ProtoTCP,
			State:     state,
			Listening: state == "LISTEN",
			PID:       int32(r.OwningPID),
		})
	}
	return out, nil
}

// UDP tables carry only the local end: a datagram socket has no fixed peer.
// These arrive as listeners, which is correct, and the normalizer drops them
// rather than inventing a flow.
func (s *iphlpapiSampler) udp4() ([]types.Conn, error) {
	buf, err := table(procGetExtendedUDPTab, windows.AF_INET, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	var out []types.Conn
	for _, r := range rows[mibUDPRowOwnerPID](buf) {
		out = append(out, types.Conn{
			Src:       netip.AddrPortFrom(addr4(r.LocalAddr), port(r.LocalPort)),
			Proto:     types.ProtoUDP,
			Listening: true,
			PID:       int32(r.OwningPID),
		})
	}
	return out, nil
}

func (s *iphlpapiSampler) udp6() ([]types.Conn, error) {
	buf, err := table(procGetExtendedUDPTab, windows.AF_INET6, udpTableOwnerPID)
	if err != nil {
		return nil, err
	}
	var out []types.Conn
	for _, r := range rows[mibUDP6RowOwnerPID](buf) {
		out = append(out, types.Conn{
			Src:       netip.AddrPortFrom(addr16(r.LocalAddr), port(r.LocalPort)),
			Proto:     types.ProtoUDP,
			Listening: true,
			PID:       int32(r.OwningPID),
		})
	}
	return out, nil
}

// addr4 converts a DWORD address. It is already in network byte order, so its
// bytes are the address bytes in order.
func addr4(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func addr16(b [16]byte) netip.Addr {
	a := netip.AddrFrom16(b)
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// port extracts the port from a DWORD holding it in network byte order in the
// low two bytes.
func port(v uint32) uint16 {
	return uint16(v&0xff)<<8 | uint16((v>>8)&0xff)
}

// MIB_TCP_STATE values from tcpmib.h, indexed from 1.
var windowsTCPStates = []string{
	"", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
	"FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK",
	"TIME_WAIT", "DELETE_TCB",
}

func windowsTCPState(s uint32) string {
	if s < uint32(len(windowsTCPStates)) {
		return windowsTCPStates[s]
	}
	return ""
}

// processInfo resolves a PID to an executable name.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberately the weakest right that
// works: it is enough for the image path and, unlike the full query right, is
// granted for processes owned by other users without elevation. Anything we
// still cannot open simply arrives without a name.
func processInfo(pid uint32) procInfo {
	// **Unattributed, not "System Idle Process".**
	//
	// Windows reports owning PID 0 when the owner is unknown or already gone,
	// which is the ordinary state of a socket in TIME_WAIT. The idle process is
	// a scheduler bookkeeping fiction with no handle table; it has never opened
	// a socket and never will.
	//
	// Naming it here put "System Idle Process" in the application column of the
	// dashboard beside real destinations, which is not a cosmetic wart: this
	// product's claim is that it names the application responsible for each
	// connection, and an answer that cannot be true is worse than no answer.
	// Found the first time Deputy Mode was run on Windows, sitting next to
	// OneDrive and Teams on live traffic.
	//
	// Returning nothing leaves the connection unattributed, which the rest of
	// the pipeline already handles: it is the same result as a process this
	// account may not open.
	if pid == 0 {
		return procInfo{}
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return procInfo{}
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return procInfo{}
	}
	path := windows.UTF16ToString(buf[:size])
	return procInfo{
		// friendlyName also copes with binaries installed under a version
		// number, which is as common on Windows as anywhere else.
		name: friendlyName(trimExe(path)),
		path: path,
	}
}

// trimExe drops the .exe suffix, which is noise in a UI.
func trimExe(path string) string {
	if ext := filepath.Ext(path); ext == ".exe" || ext == ".EXE" {
		return path[:len(path)-len(ext)]
	}
	return path
}
