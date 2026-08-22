# Seeing the whole network

Patrol Mode captures packets, which is the only way to observe a device that
cannot run software: a television, a thermostat, a doorbell, a printer. Deputy
Mode can never see those, and neither can peer sharing, because you cannot
install a binary on a doorbell.

But privilege alone is not enough, and this is the part most tools leave you to
discover for yourself.

## Why an empty Roster is usually not an empty network

A network switch is not a hub. It learns which device sits behind which port and
forwards each frame only to the port that needs it. So a machine plugged into a
switch, even with full capture privilege and promiscuous mode enabled, sees:

- its own traffic,
- broadcast and multicast traffic (ARP, mDNS, DHCP, SSDP),
- and nothing else.

That is enough for device *discovery* (which is why the Roster still fills in)
but not for seeing what those devices send to the internet.

LAN Sheriff says this in the capability hint rather than letting you conclude
your network is quiet. If Patrol Mode is capturing and you still only see this
machine's connections, you need a vantage point.

## The options, best first

### 1. Run it on your router, if your router can run it

The gateway sees everything by definition: every packet leaving the network
passes through it. Where this works it is the whole answer, and there is nothing
else to configure, Patrol Mode picks the LAN-facing interface automatically.

The catch is that "run it on your router" is advice most routers cannot take,
and it is worth being precise about which can:

| Router | Patrol Mode |
|---|---|
| A Linux box or mini-PC acting as gateway (Debian, Ubuntu, Fedora) | **Yes.** The `linux_amd64` or `linux_arm64` release |
| A Raspberry Pi routing or bridging, 64-bit Pi OS | **Yes.** The `linux_arm64` release |
| Stock consumer firmware, TP-Link, Asus, Netgear, an ISP box | **No.** Nothing can be installed on it |
| OpenWrt | **Not yet.** See below |
| pfSense or OPNsense | **Not yet.** See below |

**OpenWrt** builds against musl, and the Linux capture release links glibc
dynamically, deliberately, because a fully static glibc binary breaks name
resolution. So the released binary will not start there. Many OpenWrt devices
are also mips or mipsel, which nothing in the release matrix targets. Reaching
OpenWrt properly means a musl build, and that is packaging work not yet done.

**pfSense and OPNsense** are FreeBSD, and FreeBSD is currently reached only by
the *portable* build, which is cgo-free and therefore has no packet capture at
all. A BSD firewall is close to the ideal vantage point, and shipping it without
Patrol Mode is the least defensible gap in the matrix. Worth saying plainly:
OPNsense does not run on a Raspberry Pi.

Until those two exist, a small always-on Linux machine between your modem and
your switch is the arrangement that actually delivers what this section
promises.

### 2. A mirror or SPAN port

Managed switches can copy all traffic from one port (or the whole switch) to a
monitoring port. Plug the LAN Sheriff machine into that port.

Terminology differs by vendor: Cisco calls it SPAN, most others call it port
mirroring. Mirror the *uplink* port (the one going to your router) since that
is where internet-bound traffic crosses.

### 3. Inline between router and switch

A machine with two network interfaces, bridging them, sees everything that
crosses. Effective, but it puts your whole network's connectivity behind one
box; only worth it if you are comfortable with that.

### 4. A Raspberry Pi on the mirror port

The cheapest permanent arrangement, and the one LAN Sheriff is built for.
Storage is bounded and self-pruning specifically so this can be left running for
weeks without attention.

## What will not work

**Wi-Fi in promiscuous mode.** Modern Wi-Fi is encrypted per-client (WPA2/WPA3),
so even in monitor mode you cannot read your neighbours', or your own other
devices', traffic. There is no configuration that fixes this.

**A machine plugged into an ordinary unmanaged switch.** No mirroring
capability, so no visibility. Unmanaged switches with mirroring exist but are
uncommon.

**A virtual machine on a NAT'd adapter.** You will see the hypervisor's virtual
network and nothing of the real one.

## The privilege side

Separate from the vantage point, capture needs permission:

| Platform | What is needed |
|---|---|
| Linux | `sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-sheriff)`, preferable to running as root |
| macOS | Access to the BPF devices, which in practice means `sudo` |
| Windows | [Npcap](https://npcap.com) installed, and run as Administrator |

Patrol Mode is also a build-time option, because packet capture requires libpcap
and therefore cgo. The default build is deliberately cgo-free so that
cross-compiling to a Pi and `go install` both stay trivial:

```sh
make patrol      # builds with capture support
```

Without it, LAN Sheriff runs in Deputy Mode and tells you what you would gain.

## What you get without any of this

Deputy Mode needs no privilege, no vantage point and no special build, and it
does something Patrol Mode structurally cannot: name the **application** behind
every connection. Packets carry no notion of a process.

So the two modes are not a ladder, they are complementary. Deputy tells you
*which app*; Patrol tells you *which devices*. Running both, which is the
default when capture is available, gives you both answers.

One special case worth knowing: if this machine is your network's DNS resolver
(running Pi-hole, dnsmasq or Unbound), Deputy Mode detects that and Radio
Chatter works without any capture privilege at all, because the lookups are
already arriving at this host.
