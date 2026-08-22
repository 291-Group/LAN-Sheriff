package netutil

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// PublicIP discovers this network's own external address, which is the only way
// to place the map's origin, nothing observable from inside the network says
// where it is.
//
// The DNS route is tried first and deliberately: a TXT query to a resolver that
// answers with the querier's address discloses nothing that sending the query
// did not already disclose. The HTTPS fallback exists for networks that block
// or intercept external resolvers.
//
// This is the only outbound request LAN Sheriff makes about *you* rather than
// about a dataset, and it can be switched off entirely (--no-locate), in which
// case arcs are drawn from a neutral origin.
func PublicIP(ctx context.Context) (netip.Addr, bool) {
	if addr, ok := publicIPviaDNS(ctx); ok {
		return addr, true
	}
	return publicIPviaHTTPS(ctx)
}

// publicIPviaDNS asks OpenDNS's special myip.opendns.com record, which resolves
// to the address of whoever asked.
func publicIPviaDNS(ctx context.Context) (netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	for _, resolver := range []string{"208.67.222.222:53", "208.67.220.220:53"} {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", resolver)
			},
		}
		ips, err := r.LookupHost(ctx, "myip.opendns.com")
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if addr, err := netip.ParseAddr(ip); err == nil && IsRoutable(addr) {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

func publicIPviaHTTPS(ctx context.Context) (netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return netip.Addr{}, false
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return netip.Addr{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil || !IsRoutable(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}
