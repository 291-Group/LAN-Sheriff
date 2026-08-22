package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
)

// The shared machinery behind the mDNS and SSDP listeners.
//
// Both work the same way: join a well-known IPv4 multicast group, then read the
// announcements devices broadcast anyway. That is the important property, this
// is *passive*. Devices on a home network advertise themselves continuously
// without being asked, so simply listening builds a device list while putting
// nothing on the wire.
//
// Listening needs no privilege: both ports are above 1024 and joining a group is
// an ordinary socket operation. So the Roster works for every user, not only
// those who can grant packet-capture rights.

// multicastPacket is one datagram received on a group, with its sender.
type multicastPacket struct {
	From netip.AddrPort
	// Interface is the local interface it arrived on, used to ignore traffic
	// from container bridges and VPNs.
	Interface string
	Data      []byte
}

// listenMulticast joins group:port on every suitable interface and delivers
// datagrams to handle until ctx is cancelled.
//
// A join that fails on one interface is not fatal: a machine typically has
// several, and only some carry the local network. The call fails only when no
// interface could be joined at all.
func listenMulticast(
	ctx context.Context,
	group netip.Addr,
	port int,
	bufSize int,
	handle func(multicastPacket),
) error {
	lc := net.ListenConfig{Control: reusePort}

	// Bind the wildcard address rather than the group: binding the group address
	// is a BSD-ism that does not work on Windows, and the wildcard plus an
	// explicit join is portable.
	conn, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("bind udp4 port %d: %w", port, err)
	}

	p := ipv4.NewPacketConn(conn)
	// The interface index of each datagram is needed to tell LAN traffic from a
	// container bridge's, and it is only available if this is requested.
	if err := p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		// Not fatal: without it every packet is simply treated as un-attributed.
		_ = err
	}

	joined, names := joinOnAll(p, group, port)
	if joined == 0 {
		conn.Close()
		return fmt.Errorf("could not join %s on any interface", group)
	}

	go func() {
		defer conn.Close()
		<-ctx.Done()
	}()

	go func() {
		buf := make([]byte, bufSize)
		for {
			n, cm, src, err := p.ReadFrom(buf)
			if err != nil {
				// A closed socket after cancellation is the expected exit.
				if ctx.Err() != nil {
					return
				}
				// A single bad read should not end discovery for the session.
				continue
			}
			if n == 0 {
				continue
			}
			// src is always a *net.UDPAddr for a udp4 socket; converting
			// directly avoids formatting and reparsing an address on every
			// packet.
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				continue
			}
			from, ok := netip.AddrFromSlice(ua.IP)
			if !ok {
				continue
			}
			ap := netip.AddrPortFrom(from.Unmap(), uint16(ua.Port))
			var ifname string
			if cm != nil {
				ifname = names[cm.IfIndex]
			}
			// Copy: the buffer is reused on the next read, and handlers may keep
			// what they are given.
			data := make([]byte, n)
			copy(data, buf[:n])

			handle(multicastPacket{From: ap, Interface: ifname, Data: data})
		}
	}()

	return nil
}

// joinOnAll joins the group on every interface that could plausibly carry local
// network traffic, returning how many succeeded and an index-to-name map.
func joinOnAll(p *ipv4.PacketConn, group netip.Addr, port int) (int, map[int]string) {
	names := map[int]string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, names
	}

	target := &net.UDPAddr{IP: group.AsSlice(), Port: port}
	joined := 0

	for i := range ifaces {
		iface := ifaces[i]
		names[iface.Index] = iface.Name

		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		// Loopback carries no other devices, and a container bridge or VPN
		// carries devices the user would not call theirs.
		if iface.Flags&net.FlagLoopback != 0 || isVirtualInterface(iface.Name) {
			continue
		}
		if err := p.JoinGroup(&iface, target); err != nil {
			continue
		}
		joined++
	}
	return joined, names
}

// Packet is one datagram received on a multicast group.
//
// Exported alongside ListenMulticast for The Dispatch, which needs the same
// join-and-read machinery on a different group. Duplicating it there would mean
// two implementations of the interface-selection and SO_REUSEPORT handling that
// took several platform quirks to get right.
type Packet = multicastPacket

// ListenMulticast joins group:port on every suitable interface and delivers
// datagrams until ctx is cancelled.
//
// The same passive listener the Roster is built on. It puts nothing on the wire;
// senders are a separate concern for the caller.
func ListenMulticast(
	ctx context.Context,
	group netip.Addr,
	port int,
	bufSize int,
	handle func(Packet),
) error {
	return listenMulticast(ctx, group, port, bufSize, handle)
}
