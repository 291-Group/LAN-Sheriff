//go:build !linux && !darwin && !windows && !freebsd && !netbsd && !openbsd

package discover

import "syscall"

// No port-sharing option known for this platform. The bind is attempted plainly:
// it succeeds where nothing else holds the port, and the listener reports itself
// unavailable where something does.
func reusePort(_, _ string, _ syscall.RawConn) error { return nil }
