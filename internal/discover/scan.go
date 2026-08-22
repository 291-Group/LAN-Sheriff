package discover

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// The on-demand port check.
//
// Everything else in this package is passive or near enough. This is not: it
// opens connections to a device to see what answers. So it is bound by rules the
// rest does not need:
//
//   - **It only ever runs when a person asks for it**, on one device they chose.
//     Nothing schedules it, and there is no "scan all devices" anywhere.
//   - It checks a short list of ports a home device plausibly runs, not a range.
//     Sweeping 65,535 ports is a different act with a different name, and this
//     product has no reason to perform it.
//   - It opens a connection and closes it immediately. No banner grabbing, no
//     payload, nothing written.
//
// The result is a better answer to "what is this thing" for a device that
// advertises nothing, the silent box in the corner that mDNS and SSDP cannot
// describe.

// scanTimeout is how long a single port is given to answer.
//
// Short: this is a local network, where a listening port answers in
// milliseconds. A longer timeout would only lengthen the wait for the closed
// ports, which are the majority.
const scanTimeout = 600 * time.Millisecond

// scanConcurrency bounds how many ports are checked at once.
//
// Enough to finish in about a second, few enough that the target never sees a
// burst of dozens of simultaneous connections.
const scanConcurrency = 8

// OpenPort is a port that answered.
type OpenPort struct {
	Port    uint16 `json:"port"`
	Service string `json:"service,omitempty"`
}

// ScanPorts checks the conventional ports on one address and reports which
// answered.
//
// The caller is responsible for this being a deliberate, user-initiated act.
func ScanPorts(ctx context.Context, addr netip.Addr) ([]OpenPort, error) {
	ports := scanList()

	var (
		mu   sync.Mutex
		open []OpenPort
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, scanConcurrency)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(p uint16) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			d := net.Dialer{Timeout: scanTimeout}
			conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, p).String())
			if err != nil {
				return
			}
			// Closed at once. Nothing is written and nothing is read: the
			// question was only whether something is listening.
			conn.Close()

			mu.Lock()
			open = append(open, OpenPort{Port: p, Service: ServiceForPort(p, "tcp")})
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open, nil
}

// scanList is the ports checked, in ascending order.
//
// Exactly the table used to name observed ports, there is no reason to knock on
// a door whose answer we could not interpret.
func scanList() []uint16 {
	out := make([]uint16, 0, len(tcpPorts))
	for p := range tcpPorts {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ScanPortCount is how many ports a check covers, for the UI to say so before
// the user asks for one.
func ScanPortCount() int { return len(tcpPorts) }
