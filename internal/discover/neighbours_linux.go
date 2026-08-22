//go:build linux

package discover

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"time"
)

// /proc/net/arp is the simplest of the three platforms: a plain text table,
// world-readable, no syscalls.
//
// It covers IPv4 only. IPv6 neighbours live in the kernel's neighbour table and
// need netlink to read, which is a larger job for a smaller return: on a home
// network almost every device has an IPv4 address, and the listeners pick up the
// v6-only ones.
func neighbours() ([]Neighbour, error) {
	root := "/proc"
	if v := os.Getenv("LAN_SHERIFF_PROC_ROOT"); v != "" {
		root = v
	}

	f, err := os.Open(root + "/net/arp")
	if err != nil {
		// Not an error worth surfacing: a container without /proc mounted simply
		// has no neighbour table to read.
		return nil, nil
	}
	defer f.Close()

	var out []Neighbour
	now := time.Now()
	sc := bufio.NewScanner(f)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		// IP address  HW type  Flags  HW address  Mask  Device
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		mac := NormalizeMAC(fields[3])
		if len(mac) != 12 || mac == "000000000000" {
			// An incomplete entry: the kernel has an address but no answer yet.
			continue
		}
		out = append(out, Neighbour{
			Addr:      addr,
			MAC:       formatMAC(mac),
			Interface: fields[5],
			SeenAt:    now,
		})
	}
	return out, sc.Err()
}
