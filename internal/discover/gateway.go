package discover

import "net/netip"

// The default gateway is the most reliable device signal there is.
//
// Whatever a device's badge or advertisements say, the machine the operating
// system routes the internet through is the router. Vendor guessing is a
// coin-toss for manufacturers who make several categories; this is not a guess
// at all.
//
// It is also the anchor for the Precinct Map: every other device on the segment
// hangs off it.

// DefaultGateway returns the address of the network's default route.
//
// An invalid address means it could not be determined, which is not an error:
// device typing falls back to its other signals.
func DefaultGateway() netip.Addr { return defaultGateway() }
