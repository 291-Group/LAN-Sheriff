//go:build patrol

package patrol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"

	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Built reports whether packet capture is compiled into this binary (compiled with -tags patrol).
// A constant rather than a runtime check: it is a property of the build, and
// the dashboard needs to say which of the two programs somebody is holding.
const Built = true

// libpcap's PCAP_IF_* interface flags. gopacket exposes Interface.Flags as a
// bare uint32 without naming the bits, so they are named here rather than left
// as magic numbers at each use.
const (
	pcapIfLoopback = 0x00000001
	pcapIfUp       = 0x00000002
	pcapIfRunning  = 0x00000004
)

// Not every platform populates these flags. Where they are all zero, treating
// that as "interface is down" would disqualify every device and leave automatic
// selection with nothing, so absent flags mean unknown rather than false.
func flagsKnown(flags uint32) bool { return flags != 0 }

func ifaceIsUp(flags uint32) bool {
	if !flagsKnown(flags) {
		return true
	}
	return flags&pcapIfUp != 0 || flags&pcapIfRunning != 0
}

func ifaceIsLoopback(flags uint32) bool { return flags&pcapIfLoopback != 0 }

func available() bool { return true }

func interfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list capture interfaces: %w", err)
	}

	best := recommendInterface(devs)
	out := make([]Interface, 0, len(devs))
	for _, d := range devs {
		iface := Interface{
			Name:        d.Name,
			Description: d.Description,
			Up:          ifaceIsUp(d.Flags),
			Loopback:    ifaceIsLoopback(d.Flags),
			Recommended: d.Name == best,
		}
		for _, a := range d.Addresses {
			if a.IP != nil {
				iface.Addresses = append(iface.Addresses, a.IP.String())
			}
		}
		out = append(out, iface)
	}
	return out, nil
}

// recommendInterface picks the device most likely to carry the network's
// traffic: up, not loopback, and holding a private address. A Docker bridge or
// VPN tunnel would technically capture, but seeing only container traffic while
// believing you were watching the network is worse than seeing nothing.
func recommendInterface(devs []pcap.Interface) string {
	type scored struct {
		name  string
		score int
	}
	var best scored

	for _, d := range devs {
		if !ifaceIsUp(d.Flags) || ifaceIsLoopback(d.Flags) {
			continue
		}
		score := 0
		for _, a := range d.Addresses {
			if a.IP == nil {
				continue
			}
			if addr, ok := netutil.AddrFromIP(a.IP); ok && netutil.IsInternal(addr) && addr.Is4() {
				score += 10
			}
		}
		if score == 0 {
			continue
		}
		// **The interface the operating system actually routes through wins.**
		//
		// Everything else here is a guess dressed up as a score. On a machine
		// with one network that is fine, because the guess and the answer are
		// the same interface. On a machine with two it is a coin flip, and it
		// came up wrong: a Windows PC with Ethernet as its main link and Wi-Fi
		// also connected got Wi-Fi, so Patrol captured a network the user was
		// not using and the two machines they were trying to pair with, both on
		// the Ethernet side, were invisible. Nothing said which interface had
		// been chosen or why, so it looked like pairing was broken.
		//
		// The routing table already knows. A UDP connect to an address that is
		// never sent to makes the kernel select a source address exactly as it
		// would for real traffic, which is the definition of "the network this
		// machine is on" and is not a heuristic at all.
		if primary, ok := primaryAddr(); ok {
			for _, a := range d.Addresses {
				if addr, ok2 := netutil.AddrFromIP(a.IP); ok2 && addr == primary {
					score += 1000
				}
			}
		}
		// Prefer a physical-looking adapter, for the same reason Deputy Mode does.
		score += 20 - min(interfacePenalty(d.Name, d.Description), 20)
		if score > best.score {
			best = scored{d.Name, score}
		}
	}
	return best.name
}

// describeInterface looks up a device's human-readable description.
//
// Only for the log line, and best effort: if the lookup fails there is nothing
// useful to say and the name is printed on its own, exactly as before.
func describeInterface(name string) string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}
	for _, d := range devs {
		if d.Name == name {
			return d.Description
		}
	}
	return ""
}

// interfacePenalty scores how unlikely a device is to be the adapter carrying
// this network's traffic. Lower is better.
//
// **The device name is a Unix idea.** On Linux and macOS it carries the answer
// in itself: en0, eth0, wlan0, docker0, utun3. On Windows every device is named
// \Device\NPF_{GUID}, so every prefix below missed, every adapter scored
// identically, and the choice fell to whichever pcap happened to enumerate
// first. On a machine with WSL2, Hyper-V, VirtualBox or a VPN client installed
// that is often a virtual switch which carries no real traffic, and the only
// clue was an opaque GUID in the log. A tester's Windows machine showed exactly
// that: flows and TLS names arriving, the DNS feed permanently empty.
//
// Windows puts the readable identity in the description instead, which the
// dashboard's interface list was already being given and this was ignoring.
//
// Penalties are checked before rewards on purpose. "Hyper-V Virtual Ethernet
// Adapter" contains the word ethernet, so rewarding that first would promote
// the exact adapter this is meant to avoid.
func interfacePenalty(name, desc string) int {
	n := strings.ToLower(name)
	d := strings.ToLower(desc)

	has := func(hay string, needles ...string) bool {
		for _, needle := range needles {
			if strings.Contains(hay, needle) {
				return true
			}
		}
		return false
	}

	switch {
	// Virtual switches and host-only adapters, by name (Unix) or by
	// description (Windows).
	case strings.HasPrefix(n, "docker"), strings.HasPrefix(n, "br-"),
		strings.HasPrefix(n, "veth"), strings.HasPrefix(n, "virbr"),
		strings.HasPrefix(n, "vmnet"), strings.HasPrefix(n, "bridge"):
		return 18
	case has(d, "virtual", "vmware", "virtualbox", "hyper-v", "vethernet",
		"docker", "loopback", "wan miniport", "bluetooth", "wi-fi direct"):
		return 18

	// Tunnels. They carry real traffic, but watching one and believing you are
	// watching the network is the misunderstanding this ordering exists to
	// prevent.
	case strings.HasPrefix(n, "utun"), strings.HasPrefix(n, "tun"),
		strings.HasPrefix(n, "tap"), strings.HasPrefix(n, "wg"),
		strings.HasPrefix(n, "tailscale"), strings.HasPrefix(n, "ppp"):
		return 12
	case has(d, "tap-", "tun ", "tailscale", "wireguard", "openvpn",
		"zerotier", "vpn", "warp"):
		return 12

	// Something that looks like real hardware.
	case strings.HasPrefix(n, "en"), strings.HasPrefix(n, "eth"),
		strings.HasPrefix(n, "wl"):
		return 0
	case has(d, "wi-fi", "wifi", "wireless", "802.11", "ethernet", "gigabit",
		"gbe", "network connection", "network adapter"):
		return 0

	default:
		return 6
	}
}

type live struct {
	mu     sync.Mutex
	handle *pcap.Handle
	cancel context.CancelFunc
	done   chan struct{}
	// active is the device capture was actually opened on. Recorded because it
	// is the one thing the automatic choice does that nobody can otherwise see:
	// on Windows the name is a GUID, the log line was the only report of it, and
	// a wrong pick is invisible until somebody notices a view is empty.
	active string
}

func newImpl() sourceImpl { return &live{} }

func (l *live) capabilities(opts Options) types.Capabilities {
	c := types.Capabilities{
		Mode:               "patrol",
		Available:          true,
		HostEgress:         true,
		OtherDevices:       true,
		ProcessAttribution: false, // packets carry no notion of a process
		ByteCounts:         true,  // measured directly, unlike socket tables
		DNSFeed:            true,
		DeviceInventory:    true,
		Topology:           "lan",
	}

	// Privilege is checkable; a vantage point is not. Opening the interface is
	// the only honest test of the former.
	if err := l.probe(opts); err != nil {
		c.Available = false
		c.OtherDevices = false
		c.DNSFeed = false
		c.DeviceInventory = false
		c.ByteCounts = false
		c.Topology = "none"
		c.Hint = "Patrol Mode cannot open a capture interface, so only this machine is visible. " + privilegeAdvice()
		c.HintCode = noPrivilegeCode()
		c.EnableCmd = privilegeCmd()
		return c
	}

	// Available, but say plainly what capture cannot promise: on a switched
	// network, privilege without a vantage point still shows almost nothing of
	// other devices, and a user seeing an empty Roster deserves to know why.
	// Not "run this on your router". README.md lists OpenWrt and BSD firewalls
	// as the two places Patrol Mode cannot reach yet, so that advice was one
	// most readers could not act on: consumer routers are musl and often mips
	// against a glibc binary, pfSense and OPNsense are FreeBSD with no capture
	// build, and 15 MB does not fit in 8 MB of flash anyway.
	// Written for somebody who does not know what a vantage point or a SPAN
	// port is, because that is who reads it. The previous version named three
	// pieces of network jargon and then described what they would not be able
	// to do, which a tester summarised as "borderline makes no sense". This one
	// answers the question they actually have, which is why the device list is
	// shorter than they expected, and says the ordinary case is normal.
	c.Hint = "Watching this machine's traffic. Other devices on your network will only appear if " +
		"this machine can see their traffic, which usually means plugging it into your router or " +
		"a switch set up to copy traffic. Most home networks do not do this, and that is normal."
	c.HintCode = types.HintPatrolNeedsVantage
	return c
}

func (l *live) probe(opts Options) error {
	name, err := l.chooseInterface(opts)
	if err != nil {
		return err
	}
	// A very short-lived open: enough to learn whether the OS will permit it.
	h, err := pcap.OpenLive(name, 64, opts.Promiscuous, 10*time.Millisecond)
	if err != nil {
		return err
	}
	h.Close()
	return nil
}

func (l *live) chooseInterface(opts Options) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("list capture interfaces: %w", err)
	}

	if opts.Interface != "" {
		if name, ok := resolveInterface(devs, opts.Interface); ok {
			return name, nil
		}
		return "", fmt.Errorf("no capture interface matches %q.\n\nAvailable:\n%s",
			opts.Interface, describeInterfaces(devs))
	}

	if name := recommendInterface(devs); name != "" {
		return name, nil
	}
	return "", errors.New("no suitable capture interface found")
}

// resolveInterface turns what a person typed into what libpcap wants.
//
// # Why this is not just a string
//
// On Linux and macOS the two are the same: `eth0` is both what `ip link` calls
// it and what pcap opens, so passing the flag straight through works. On Windows they are nothing alike. libpcap wants
// \Device\NPF_{9A8E...}, a GUID nobody can read or type, while the name on
// screen in Settings, and therefore the only name a user knows, is "Ethernet"
// or "Wi-Fi", and that lives in the device's *description*.
//
// So `--interface Ethernet` on Windows could never have worked. It failed in
// pcap.OpenLive with a message about the device not existing, which reads like
// a permissions or Npcap problem, and that is exactly how it was diagnosed:
// an hour of chasing Npcap, elevation and driver installs, for a flag that was
// never going to match. Omitting the flag worked the whole time, which made it
// look intermittent rather than wrong.
//
// Matching is widened rather than made clever: exact device name first, since
// anyone who passed a real pcap name means it, then the friendly description,
// then a unique substring of it, then an address on the interface. Ambiguity
// is refused rather than guessed at, because picking the wrong adapter to
// capture on is a silent wrong answer.
func resolveInterface(devs []pcap.Interface, want string) (string, bool) {
	want = strings.TrimSpace(want)
	if want == "" {
		return "", false
	}
	lower := strings.ToLower(want)

	// 1. The pcap device name itself, case sensitive, because that is an
	//    identifier rather than a label.
	for _, d := range devs {
		if d.Name == want {
			return d.Name, true
		}
	}

	// 2. The friendly name, which on Windows is the description and is the
	//    only name the user has ever been shown.
	for _, d := range devs {
		if strings.EqualFold(strings.TrimSpace(d.Description), want) {
			return d.Name, true
		}
	}

	// 3. An address on the interface. "--interface 192.168.1.24" is a
	//    reasonable thing to try when the names are GUIDs.
	for _, d := range devs {
		for _, a := range d.Addresses {
			if a.IP != nil && a.IP.String() == want {
				return d.Name, true
			}
		}
	}

	// 4. A substring of the description, but only if it picks out exactly one
	//    interface. "Wi-Fi" should work; a fragment matching three adapters is
	//    a question, and answering a question by guessing means capturing the
	//    wrong network and never saying so.
	var hits []string
	for _, d := range devs {
		if strings.Contains(strings.ToLower(d.Description), lower) ||
			strings.Contains(strings.ToLower(d.Name), lower) {
			hits = append(hits, d.Name)
		}
	}
	if len(hits) == 1 {
		return hits[0], true
	}
	return "", false
}

// describeInterfaces lists what could have been chosen, in the form the user
// would have to type. Printed when a name does not match, because "no such
// interface" without the alternatives sends people to the internet rather than
// to the answer, which is on their own screen.
func describeInterfaces(devs []pcap.Interface) string {
	var b strings.Builder
	for _, d := range devs {
		var ips []string
		for _, a := range d.Addresses {
			if a.IP != nil && !a.IP.IsLoopback() && a.IP.To4() != nil {
				ips = append(ips, a.IP.String())
			}
		}
		switch {
		case d.Description != "" && len(ips) > 0:
			fmt.Fprintf(&b, "  %-24s %s\n", d.Description, strings.Join(ips, ", "))
		case d.Description != "":
			fmt.Fprintf(&b, "  %-24s %s\n", d.Description, d.Name)
		case len(ips) > 0:
			fmt.Fprintf(&b, "  %-24s %s\n", d.Name, strings.Join(ips, ", "))
		default:
			fmt.Fprintf(&b, "  %s\n", d.Name)
		}
	}
	if b.Len() == 0 {
		return "  (none, which usually means capture privilege is missing)\n"
	}
	return b.String()
}

func (l *live) start(ctx context.Context, opts Options, out chan<- types.RawEvent) error {
	name, err := l.chooseInterface(opts)
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(name, int32(opts.SnapshotLen), opts.Promiscuous, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w (%s)", name, err, privilegeAdvice())
	}
	l.mu.Lock()
	l.active = name
	l.mu.Unlock()

	// Capture only what is parsed. A BPF filter runs in the kernel, so traffic
	// this never looks at costs nothing to ignore, which is what makes leaving
	// capture running on a Pi viable.
	if err := handle.SetBPFFilter("ip or ip6 or arp"); err != nil {
		handle.Close()
		return fmt.Errorf("set filter on %s: %w", name, err)
	}

	l.mu.Lock()
	if l.cancel != nil {
		l.mu.Unlock()
		handle.Close()
		return errors.New("patrol: already started")
	}
	ctx, cancel := context.WithCancel(ctx)
	l.handle, l.cancel = handle, cancel
	l.done = make(chan struct{})
	done := l.done
	l.mu.Unlock()

	// The description as well as the name. On Windows the name is a GUID, so a
	// log line carrying only that cannot answer the first question anybody asks
	// when the feed looks wrong: which adapter is this actually watching.
	// The description only exists on Windows, where the interface name is a
	// GUID and useless on its own. Linux and macOS leave it empty, so it is
	// omitted rather than logged as an empty pair on every platform that does
	// not need it.
	args := []any{"interface", name}
	if desc := describeInterface(name); desc != "" {
		args = append(args, "adapter", desc)
	}
	args = append(args, "promiscuous", opts.Promiscuous, "snaplen", opts.SnapshotLen)
	slog.Info("patrol capture started", args...)

	// **Say so when there was more than one network to choose from.**
	//
	// A machine with Ethernet and Wi-Fi both connected is ordinary, and until
	// now capture picked one and said nothing about the other. When the pick
	// was wrong the symptom was not an error: it was a dashboard that worked,
	// showed some devices, and simply never showed the machines the user was
	// trying to pair with, because those were on the other network. There is
	// no way to reason from that to "wrong adapter" without already knowing
	// this choice existed.
	if opts.Interface == "" {
		if others := otherCandidates(name); len(others) > 0 {
			slog.Warn("more than one network is connected; capturing the one this machine routes through",
				"capturing", firstNonEmpty(describeInterface(name), name),
				"not capturing", strings.Join(others, ", "),
				"change with", "--interface \"<name from the list above>\"")
		}
	}

	go l.run(ctx, done, handle, opts, out)
	return nil
}

func (l *live) run(
	ctx context.Context, done chan struct{}, handle *pcap.Handle,
	opts Options, out chan<- types.RawEvent,
) {
	defer close(done)
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	// Lazy and NoCopy: only the layers actually inspected get decoded, and the
	// kernel's buffer is read in place. At line rate this is the difference
	// between keeping up and dropping packets.
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	assembler := newFlowAssembler(opts.DeviceID)
	flush := time.NewTicker(flowFlushInterval)
	defer flush.Stop()

	packets := src.Packets()
	for {
		select {
		case <-ctx.Done():
			l.emitFlows(ctx, assembler.expireAll(), out)
			return

		case pkt, ok := <-packets:
			if !ok {
				return
			}
			l.handlePacket(ctx, pkt, assembler, out)

		case <-flush.C:
			l.emitFlows(ctx, assembler.expire(time.Now()), out)
		}
	}
}

func (l *live) handlePacket(
	ctx context.Context, pkt gopacket.Packet,
	assembler *flowAssembler, out chan<- types.RawEvent,
) {
	// Application-layer signals are parsed for labelling only. No payload is
	// ever stored: the DNS name, the TLS server name and the HTTP host are the
	// entire extent of what is taken from a packet's contents.
	if dns := parseDNS(pkt); dns != nil {
		select {
		case out <- types.RawEvent{Kind: types.KindDNS, Source: "patrol", TS: dns.TS, DNS: dns}:
		case <-ctx.Done():
			return
		}
	}
	// A device asking for an address says more about itself in one exchange than
	// in hours of ordinary traffic.
	if sighting := parseDHCP(pkt); sighting != nil {
		sighting.SeenAt = time.Now()
		select {
		case out <- types.RawEvent{
			Kind: types.KindSighting, Source: "patrol",
			TS: sighting.SeenAt, Sighting: sighting,
		}:
		case <-ctx.Done():
			return
		}
	}
	assembler.observe(pkt)
}

func (l *live) emitFlows(ctx context.Context, conns []types.Conn, out chan<- types.RawEvent) {
	for i := range conns {
		select {
		case out <- types.RawEvent{
			Kind:   types.KindConnDelta,
			Source: "patrol",
			TS:     time.Now(),
			Conn:   &conns[i],
		}:
		case <-ctx.Done():
			return
		}
	}
}

func (l *live) stop() error {
	l.mu.Lock()
	cancel, done, handle := l.cancel, l.done, l.handle
	l.cancel, l.handle = nil, nil
	l.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	// pcap.BlockForever means the read may be parked in the kernel; closing the
	// handle is what releases it.
	if handle != nil {
		handle.Close()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		slog.Warn("patrol capture did not stop promptly")
	}
	return nil
}

// privilegeAdvice explains what is missing, per platform.
// noPrivilegeCode names the platform, so the reader is not handed three
// platforms' instructions and left to pick. The generic code remains for
// anything not listed, where a specific instruction would be a guess.
func noPrivilegeCode() string {
	switch runtime.GOOS {
	case "linux":
		return types.HintPatrolNoPrivilegeLinux
	case "darwin":
		return types.HintPatrolNoPrivilegeMacOS
	case "windows":
		return types.HintPatrolNoPrivilegeWindows
	default:
		return types.HintPatrolNoPrivilege
	}
}

func privilegeAdvice() string {
	switch runtime.GOOS {
	case "linux":
		return "Grant packet-capture capability, or run as root."
	case "darwin":
		return "Capture needs access to the BPF devices, which usually means running with sudo."
	case "windows":
		// The address, not just the name. "Install Npcap" tells somebody what is
		// missing and leaves them to go and find it, which is the same backtrack
		// this message exists to prevent.
		return "Install Npcap from https://npcap.com, then run as Administrator."
	default:
		return "Packet capture needs elevated privileges."
	}
}

func privilegeCmd() string {
	switch runtime.GOOS {
	case "linux":
		return "sudo setcap cap_net_raw,cap_net_admin=eip " + selfPath()
	case "darwin":
		return "sudo " + selfPath()
	case "windows":
		return "Run as Administrator (Npcap required)"
	default:
		return "sudo " + selfPath()
	}
}

// selfPath is the path of the running binary, for a command somebody is meant
// to copy and run.
//
// This used to print `$(which lan-sheriff)`. On a machine where the binary is
// not on PATH, which is every machine where somebody downloaded it and ran it
// from their home directory, that expands to nothing: the command becomes
// `sudo setcap cap_net_raw,cap_net_admin=eip` with no file and fails. The
// dashboard was handing a broken command to precisely the person least able to
// spot why, on the one screen whose whole job is to get them unstuck. Found on
// a Raspberry Pi running from ~/lan-sheriff.
//
// Falls back to the plain name only if the path cannot be determined at all,
// which is no worse than what it printed before.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return "lan-sheriff"
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	// Quoted only when it needs to be, so the ordinary case stays copyable.
	if strings.ContainsAny(exe, " \t'\"") {
		return "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
	}
	return exe
}

// activeInterface reports the device capture is open on, empty when it is not
// running.
func (l *live) activeInterface() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

// primaryAddr is the local address this machine would use to reach the
// internet, according to the routing table rather than to inference.
//
// The UDP "connect" sends nothing: for a datagram socket it only fixes the
// local endpoint, and the kernel fixes it by consulting the same routes real
// traffic uses. The destination is TEST-NET-1, which is reserved by RFC 5737
// and routed nowhere, so even a stray packet could not leave.
func primaryAddr() (netip.Addr, bool) {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	addr, ok := netutil.AddrFromIP(ua.IP)
	return addr, ok
}

// otherCandidates names the connected networks that were not chosen, in the
// form the user would type to choose one.
func otherCandidates(chosen string) []string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range devs {
		if d.Name == chosen || !ifaceIsUp(d.Flags) || ifaceIsLoopback(d.Flags) {
			continue
		}
		routable := false
		for _, a := range d.Addresses {
			if addr, ok := netutil.AddrFromIP(a.IP); ok && netutil.IsInternal(addr) && addr.Is4() {
				routable = true
			}
		}
		if routable {
			out = append(out, firstNonEmpty(strings.TrimSpace(d.Description), d.Name))
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
