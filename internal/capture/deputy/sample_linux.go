//go:build linux

package deputy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// procSampler reads the socket tables out of /proc.
//
// The inode->PID mapping costs a walk of /proc/<pid>/fd, so it is cached and
// only refreshed when a socket turns up whose inode we have not seen before. A
// netlink sock_diag implementation would be cheaper at scale and would
// additionally carry per-connection byte counters via INET_DIAG_INFO, that is
// the upgrade path, not an M1 requirement.
type procSampler struct {
	root string // "/proc", overridable for tests

	inodeToPID map[uint64]int32
	procs      map[int32]procInfo
}

// row pairs a parsed connection with the socket inode identifying its owner.
type row struct {
	conn  types.Conn
	inode uint64
}

func newSampler() (sampler, error) {
	root := "/proc"
	if v := os.Getenv("LAN_SHERIFF_PROC_ROOT"); v != "" {
		root = v
	}
	if _, err := os.Stat(filepath.Join(root, "net")); err != nil {
		return nil, fmt.Errorf("cannot read %s/net: %w", root, err)
	}
	return &procSampler{
		root:       root,
		inodeToPID: make(map[uint64]int32),
		procs:      make(map[int32]procInfo),
	}, nil
}

// byteCounts reports false: /proc/net/{tcp,udp} exposes queue depths, not
// cumulative byte counters.
func (s *procSampler) byteCounts() bool { return false }

func (s *procSampler) close() error { return nil }

var procTables = []struct {
	file  string
	proto types.Proto
	v6    bool
}{
	{"net/tcp", types.ProtoTCP, false},
	{"net/tcp6", types.ProtoTCP, true},
	{"net/udp", types.ProtoUDP, false},
	{"net/udp6", types.ProtoUDP, true},
}

func (s *procSampler) sample() ([]types.Conn, error) {
	var rows []row
	var parsed int
	for _, t := range procTables {
		got, err := s.parseTable(filepath.Join(s.root, t.file), t.proto, t.v6)
		if err != nil {
			// A missing table is normal (no IPv6 on this box). A broken one
			// should not sink the whole sample.
			continue
		}
		parsed++
		rows = append(rows, got...)
	}
	if parsed == 0 {
		return nil, fmt.Errorf("no readable socket tables under %s", s.root)
	}

	if s.needsRefresh(rows) {
		s.refreshInodeMap()
	}

	conns := make([]types.Conn, 0, len(rows))
	for _, r := range rows {
		c := r.conn
		if pid, ok := s.inodeToPID[r.inode]; ok && r.inode != 0 {
			c.PID = pid
			if info, ok := s.procs[pid]; ok {
				c.Process = info.name
				c.ProcessPath = info.path
			}
		}
		conns = append(conns, c)
	}
	return conns, nil
}

func (s *procSampler) needsRefresh(rows []row) bool {
	for _, r := range rows {
		if r.inode == 0 {
			continue
		}
		if _, ok := s.inodeToPID[r.inode]; !ok {
			return true
		}
	}
	return false
}

func (s *procSampler) parseTable(path string, proto types.Proto, v6 bool) ([]row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows []row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, okL := parseProcAddr(fields[1], v6)
		remote, okR := parseProcAddr(fields[2], v6)
		if !okL || !okR {
			continue
		}
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		state := procState(proto, fields[3])

		rows = append(rows, row{
			conn: types.Conn{
				Src:       local,
				Dst:       remote,
				Proto:     proto,
				State:     state,
				Listening: state == "LISTEN",
			},
			inode: inode,
		})
	}
	return rows, sc.Err()
}

// parseProcAddr decodes the "HEXADDR:HEXPORT" form used throughout /proc/net.
//
// The kernel prints each 32-bit word of the address in host byte order, so on
// the little-endian architectures we target (amd64, arm64, armv7) the bytes
// come back reversed within each word. The port is printed already in host
// order, so it parses directly.
func parseProcAddr(s string, v6 bool) (netip.AddrPort, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return netip.AddrPort{}, false
	}
	hexAddr, hexPort := s[:i], s[i+1:]

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}

	var addr netip.Addr
	switch {
	case !v6 && len(hexAddr) == 8:
		v, err := strconv.ParseUint(hexAddr, 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		addr = netip.AddrFrom4(b)
	case v6 && len(hexAddr) == 32:
		var b [16]byte
		for w := 0; w < 4; w++ {
			v, err := strconv.ParseUint(hexAddr[w*8:(w+1)*8], 16, 32)
			if err != nil {
				return netip.AddrPort{}, false
			}
			binary.LittleEndian.PutUint32(b[w*4:], uint32(v))
		}
		addr = netip.AddrFrom16(b)
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(port)), true
}

var procTCPStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

func procState(proto types.Proto, hexState string) string {
	if proto != types.ProtoTCP {
		return ""
	}
	return procTCPStates[strings.ToUpper(hexState)]
}

// refreshInodeMap walks /proc/<pid>/fd and rebuilds the socket-inode to PID
// mapping. Processes we may not read (other users, without privilege) are
// skipped silently; their connections simply arrive without an owning process
// rather than not arriving at all.
func (s *procSampler) refreshInodeMap() {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return
	}
	inodeToPID := make(map[uint64]int32, len(s.inodeToPID))
	procs := make(map[int32]procInfo, len(s.procs))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := int32(pid64)

		fdDir := filepath.Join(s.root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var owned bool
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(link[len("socket:["):], "]"), 10, 64)
			if err != nil {
				continue
			}
			inodeToPID[inode] = pid
			owned = true
		}
		if !owned {
			continue
		}
		// Process names rarely change, so reuse what we already looked up.
		if info, ok := s.procs[pid]; ok {
			procs[pid] = info
		} else {
			procs[pid] = s.readProcInfo(e.Name())
		}
	}
	s.inodeToPID = inodeToPID
	s.procs = procs
}

func (s *procSampler) readProcInfo(pid string) procInfo {
	var info procInfo
	if b, err := os.ReadFile(filepath.Join(s.root, pid, "comm")); err == nil {
		info.name = strings.TrimSpace(string(b))
	}
	if p, err := os.Readlink(filepath.Join(s.root, pid, "exe")); err == nil {
		info.path = p
		if info.name == "" {
			info.name = friendlyName(p)
		}
	}
	return info
}
