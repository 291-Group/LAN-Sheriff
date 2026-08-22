//go:build linux

package discover

import (
	"bufio"
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// /proc/net/route lists routes with hexadecimal, little-endian addresses. The
// default route is the one whose destination is all zeroes.
func defaultGateway() netip.Addr {
	root := "/proc"
	if v := os.Getenv("LAN_SHERIFF_PROC_ROOT"); v != "" {
		root = v
	}
	f, err := os.Open(root + "/net/route")
	if err != nil {
		return netip.Addr{}
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gw, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gw))
		if addr := netip.AddrFrom4(b); addr.IsValid() && !addr.IsUnspecified() {
			return addr
		}
	}
	return netip.Addr{}
}
