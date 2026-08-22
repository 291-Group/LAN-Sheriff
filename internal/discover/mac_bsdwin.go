//go:build darwin || windows || freebsd || netbsd || openbsd

// The BSDs belong here for the same reason darwin does: they read neighbours by
// parsing arp(8) output, which gives interface names and hex MAC strings rather
// than the structured table Linux exposes. Leaving them off this list is what
// made the FreeBSD build fail once the file naming was corrected.

package discover

// Helpers used only by the BSD routing-socket and Windows IP-helper neighbour
// backends. Linux reads /proc/net/arp and needs neither.
//
// They live behind a build tag rather than in mac.go because staticcheck runs
// per-platform: compiled for Linux these are unreachable, and an unused-function
// error on one platform's CI job is indistinguishable from genuinely dead code.

import (
	"net"
)

func interfaceNames() map[int]string {
	out := map[int]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		out[i.Index] = i.Name
	}
	return out
}

// hexMAC renders raw hardware-address bytes as uppercase hex, which is what
// NormalizeMAC expects as input.
func hexMAC(b []byte) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hex[c>>4], hex[c&0x0f])
	}
	return string(out)
}
