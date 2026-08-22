//go:build windows

package discover

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Windows has no SO_REUSEPORT. SO_REUSEADDR there already means what
// SO_REUSEPORT means on the BSDs: it permits a second socket to bind a port that
// is already in use, which is what sharing a multicast port requires.
func reusePort(_, _ string, c syscall.RawConn) error {
	var opErr error
	if err := c.Control(func(fd uintptr) {
		opErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return opErr
}
