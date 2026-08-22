//go:build darwin

package deputy

/*
#include <stdlib.h>
#include <sys/types.h>
#include <sys/proc_info.h>
#include <libproc.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"path/filepath"
	"unsafe"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// libprocSampler enumerates per-process sockets via libproc, which is the
// documented way to get what `lsof` shows without shelling out to it.
//
// This is the one place in the default build that needs cgo. Linux and
// Windows stay cgo-free.
//
// Unprivileged, macOS only lets us inspect processes owned by the current user,
// so an unelevated run sees your own applications, which is most of what
// matters, and misses system daemons. Capabilities() carries that caveat.
type libprocSampler struct {
	procs map[int32]procInfo
}

func newSampler() (sampler, error) {
	// Confirm libproc answers at all before claiming the mode is available.
	if n := C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0); n <= 0 {
		return nil, fmt.Errorf("proc_listpids returned %d", int(n))
	}
	return &libprocSampler{procs: make(map[int32]procInfo)}, nil
}

// byteCounts reports false: socket_fdinfo carries no cumulative byte counters.
func (s *libprocSampler) byteCounts() bool { return false }

func (s *libprocSampler) close() error { return nil }

func (s *libprocSampler) sample() ([]types.Conn, error) {
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}

	var conns []types.Conn
	live := make(map[int32]procInfo, len(pids))

	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		fds, err := listFDs(pid)
		if err != nil {
			continue // not ours to inspect
		}
		var info procInfo
		var haveInfo bool

		for _, fd := range fds {
			if fd.proc_fdtype != C.PROX_FDTYPE_SOCKET {
				continue
			}
			c, ok := socketConn(pid, C.int(fd.proc_fd))
			if !ok {
				continue
			}
			if !haveInfo {
				if cached, ok := s.procs[pid]; ok {
					info = cached
				} else {
					info = readProcInfo(pid)
				}
				live[pid] = info
				haveInfo = true
			}
			c.PID = pid
			c.Process = info.name
			c.ProcessPath = info.path
			conns = append(conns, c)
		}
	}
	s.procs = live
	return conns, nil
}

func listPIDs() ([]int32, error) {
	n := C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0)
	if n <= 0 {
		return nil, fmt.Errorf("proc_listpids: %d", int(n))
	}
	// Ask for headroom: processes can appear between the sizing call and the
	// fetch.
	count := int(n)/int(unsafe.Sizeof(C.int(0))) + 32
	buf := make([]int32, count)
	got := C.proc_listpids(C.PROC_ALL_PIDS, 0, unsafe.Pointer(&buf[0]),
		C.int(len(buf)*int(unsafe.Sizeof(int32(0)))))
	if got <= 0 {
		return nil, fmt.Errorf("proc_listpids: %d", int(got))
	}
	return buf[:int(got)/int(unsafe.Sizeof(int32(0)))], nil
}

func listFDs(pid int32) ([]C.struct_proc_fdinfo, error) {
	n := C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0, nil, 0)
	if n <= 0 {
		return nil, fmt.Errorf("proc_pidinfo(PROC_PIDLISTFDS): %d", int(n))
	}
	size := int(unsafe.Sizeof(C.struct_proc_fdinfo{}))
	count := int(n)/size + 16
	buf := make([]C.struct_proc_fdinfo, count)
	got := C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0,
		unsafe.Pointer(&buf[0]), C.int(len(buf)*size))
	if got <= 0 {
		return nil, fmt.Errorf("proc_pidinfo(PROC_PIDLISTFDS): %d", int(got))
	}
	return buf[:int(got)/size], nil
}

// socketConn reads one socket file descriptor into a Conn. It returns false for
// anything that is not an IPv4/IPv6 TCP or UDP socket (unix sockets, kernel
// control sockets and so on).
func socketConn(pid int32, fd C.int) (types.Conn, bool) {
	var si C.struct_socket_fdinfo
	size := C.int(unsafe.Sizeof(si))
	if got := C.proc_pidfdinfo(C.int(pid), fd, C.PROC_PIDFDSOCKETINFO,
		unsafe.Pointer(&si), size); got != size {
		return types.Conn{}, false
	}

	var (
		in    *C.struct_in_sockinfo
		proto types.Proto
		state string
	)
	switch si.psi.soi_kind {
	case C.SOCKINFO_TCP:
		tcp := (*C.struct_tcp_sockinfo)(unsafe.Pointer(&si.psi.soi_proto))
		in = &tcp.tcpsi_ini
		proto = types.ProtoTCP
		state = darwinTCPState(int(tcp.tcpsi_state))
	case C.SOCKINFO_IN:
		in = (*C.struct_in_sockinfo)(unsafe.Pointer(&si.psi.soi_proto))
		proto = types.ProtoUDP
	default:
		return types.Conn{}, false
	}

	v6 := in.insi_vflag&C.INI_IPV6 != 0

	local, ok := darwinAddrPort(in.insi_laddr, in.insi_lport, v6)
	if !ok {
		return types.Conn{}, false
	}
	remote, ok := darwinAddrPort(in.insi_faddr, in.insi_fport, v6)
	if !ok {
		return types.Conn{}, false
	}

	return types.Conn{
		Src: local, Dst: remote, Proto: proto, State: state,
		Listening: state == "LISTEN",
	}, true
}

// darwinAddrPort decodes one of the in_sockinfo address unions. cgo renders the
// union as a raw 16-byte array: an IPv6 address occupies all of it, while an
// IPv4 address sits in the last 4 bytes (struct in4in6_addr pads with three
// leading 32-bit words). Ports are held in network byte order.
func darwinAddrPort(raw [16]byte, port C.int, v6 bool) (netip.AddrPort, bool) {
	var addr netip.Addr
	if v6 {
		addr = netip.AddrFrom16(raw)
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
	} else {
		addr = netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	}
	if !addr.IsValid() {
		return netip.AddrPort{}, false
	}
	var pb [2]byte
	binary.LittleEndian.PutUint16(pb[:], uint16(port))
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(pb[:])), true
}

// Darwin's TSI_S_* connection states, in declaration order.
var darwinTCPStates = []string{
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED",
	"CLOSE_WAIT", "FIN_WAIT1", "CLOSING", "LAST_ACK", "FIN_WAIT2", "TIME_WAIT",
}

func darwinTCPState(s int) string {
	if s < 0 || s >= len(darwinTCPStates) {
		return ""
	}
	return darwinTCPStates[s]
}

func readProcInfo(pid int32) procInfo {
	var info procInfo
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	if n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf))); n > 0 {
		info.path = string(buf[:n])
		info.name = appName(info.path)
	}
	// Outside an .app bundle, derive the name from the path, which handles
	// binaries installed under their version number. The kernel's accounting
	// name is no help there, since macOS sets it from that same filename.
	if info.name == "" {
		info.name = friendlyName(info.path)
	}
	if info.name == "" {
		nameBuf := make([]byte, 256)
		if n := C.proc_name(C.int(pid), unsafe.Pointer(&nameBuf[0]), C.uint32_t(len(nameBuf))); n > 0 {
			info.name = string(nameBuf[:n])
		}
	}
	return info
}

// appName turns an executable path into the label a person would recognize, or
// "" if the executable does not live in an .app bundle.
//
// It reports the *outermost* bundle, because that is the application the user
// thinks they are running. Chrome's renderers live at
// ".../Google Chrome.app/Contents/Frameworks/.../Google Chrome Helper.app/..."
// and belong under "Google Chrome", not under a helper the user never launched.
func appName(path string) string {
	var outermost string
	dir := path
	for dir != "/" && dir != "." && dir != "" {
		if filepath.Ext(dir) == ".app" {
			outermost = filepath.Base(dir[:len(dir)-len(".app")])
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return outermost
}
