//go:build linux || darwin || freebsd || netbsd || openbsd

package discover

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Sharing a multicast port with whatever else is already listening.
//
// This is not optional politeness. macOS runs mDNSResponder, and most Linux
// desktops run Avahi, and both hold port 5353 permanently. Without SO_REUSEPORT
// the bind fails outright with "address already in use" on exactly the machines
// this product is meant to run on.
//
// SO_REUSEADDR alone is not enough on the BSDs: there it permits binding a
// multicast address but not sharing a port with a live socket, which is what
// SO_REUSEPORT adds.
func reusePort(_, _ string, c syscall.RawConn) error {
	var opErr error
	if err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			opErr = err
			return
		}
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return opErr
}
