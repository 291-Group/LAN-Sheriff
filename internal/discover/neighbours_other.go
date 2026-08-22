//go:build !linux && !darwin && !windows && !freebsd && !netbsd && !openbsd

package discover

// No neighbour table reader for this platform. Discovery falls back to the mDNS
// and SSDP listeners, which are portable, so the Roster is thinner rather than
// empty.
func neighbours() ([]Neighbour, error) { return nil, nil }
