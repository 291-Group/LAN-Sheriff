package cli

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// portSearchRange is how many consecutive ports to try before giving up.
const portSearchRange = 12

// listen binds the requested address, and if that port is already taken and the
// user did not ask for a specific one, walks forward to the next free port.
//
// A tool that refuses to start because something unrelated holds its default
// port is a tool that failed at "run one thing and it works". The one case
// where falling back would be wrong is when the user named a port explicitly:
// then the failure is the answer they need.
func listen(addr string, explicit bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil || explicit {
		return ln, err
	}

	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, err
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return nil, err
	}

	for next := port + 1; next < port+portSearchRange; next++ {
		candidate := net.JoinHostPort(host, strconv.Itoa(next))
		ln, tryErr := net.Listen("tcp", candidate)
		if tryErr != nil {
			continue
		}
		slog.Warn("default port was busy, moved to the next free one",
			"wanted", addr, "using", candidate)
		return ln, nil
	}
	return nil, fmt.Errorf("%w (and the %d ports after it were also busy)", err, portSearchRange)
}
