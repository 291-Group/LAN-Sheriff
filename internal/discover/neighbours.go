package discover

import (
	"net/netip"
	"time"
)

// Reading the neighbour table.
//
// The single most valuable thing about this source is that it needs **no
// privilege at all**. The operating system already keeps a table mapping IP
// addresses to hardware addresses for every device it has spoken to on the local
// segment, and reading it is an ordinary unprivileged operation.
//
// That means the Roster and the Precinct Map are populated for every user, not
// only those who can grant packet-capture rights. Patrol Mode then adds what
// those devices are *sending*; discovery alone establishes that they exist, what
// their manufacturer is, and what to call them.
//
// One limit worth stating: the table only holds devices this machine has
// actually exchanged traffic with. A device that has never talked to us, and has
// not broadcast, will not appear until it does. The mDNS and SSDP listeners
// exist partly to widen that.

// Neighbour is one entry from the operating system's IP-to-MAC table.
type Neighbour struct {
	Addr netip.Addr
	MAC  string
	// Interface is the local interface the device was seen on, which is what
	// distinguishes a LAN device from something on a VPN or container bridge.
	Interface string
	// Self marks this machine, established by comparing against the local
	// interface list rather than by trusting a platform-specific table flag.
	Self bool
	// Virtual marks an entry seen on a container bridge, VPN or VM network
	// rather than a real local segment.
	Virtual bool
	SeenAt  time.Time
}

// Neighbour also records whether the entry is this machine and whether it was
// seen on a real local segment.

// Neighbours returns the devices in the operating system's IP-to-MAC table.
//
// Broadcast and multicast entries are removed, and entries on virtual
// interfaces are marked rather than dropped so that a caller can decide: the
// Roster hides them, but a diagnostic view may want them.
//
// An unsupported platform returns no entries and no error: discovery degrades to
// whatever the listeners can find, rather than failing.
func Neighbours() ([]Neighbour, error) {
	raw, err := neighbours()
	if err != nil {
		return nil, err
	}
	ips, macs := LocalAddrs()

	out := make([]Neighbour, 0, len(raw))
	for _, n := range raw {
		if !isDevice(n) {
			continue
		}
		n.Self = ips[n.Addr.Unmap()] || macs[NormalizeMAC(n.MAC)]
		n.Virtual = isVirtualInterface(n.Interface)
		out = append(out, n)
	}
	return out, nil
}
