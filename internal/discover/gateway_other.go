//go:build !linux && !darwin && !windows && !freebsd && !netbsd && !openbsd

package discover

import "net/netip"

// No route table reader for this platform. Device typing falls back to services,
// model and vendor.
func defaultGateway() netip.Addr { return netip.Addr{} }
