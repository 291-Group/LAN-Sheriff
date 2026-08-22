package discover

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Asking, once, rather than only listening.
//
// Passive discovery is correct but slow. Devices announce on their own schedule,
// so a Roster opened a minute after startup can show six devices with no names
// against any of them, which was exactly the result of the first end-to-end run.
// A person opening the Roster wants names now.
//
// One standard DNS-SD service-enumeration query prompts every device on the
// segment to answer immediately. This is the same query every macOS machine and
// every printer dialog on the network sends routinely; it is two packets and it
// is what the protocol is for. The alternative, waiting for spontaneous
// announcements, is not more polite in any way a network administrator would
// recognise, it just makes the product look broken for the first few minutes.
//
// It stays deliberately modest: the meta-query only, no per-service follow-ups,
// no unicast sweep, and at a low frequency.

// dnssdMetaQuery is the DNS-SD service enumeration name from RFC 6763 §9.
const dnssdMetaQuery = "_services._dns-sd._udp.local."

// QueryInterval is how often the enumeration query is repeated after startup.
//
// Long, because its purpose is to fill in a newly opened Roster rather than to
// track changes: the passive listeners already catch a device that joins or
// changes. Fifteen minutes is far below what a network notices and far above
// anything that could be called chatty.
const QueryInterval = 15 * time.Minute

// commonServices are queried alongside the enumeration query.
//
// The enumeration query returns service *types*, which is a list of protocols
// rather than a list of device names, a second round is needed before anything
// human-readable comes back. Asking directly for the types a household actually
// runs collapses those two rounds into one, so the Roster has names on first
// load instead of one refresh later.
//
// Kept to a short list of what is genuinely common. This is not a scan: an
// unanswered question costs one multicast packet and nothing else.
var commonServices = []string{
	"_device-info._tcp.local.",    // model and OS, published by almost everything Apple
	"_companion-link._tcp.local.", // iPhones, iPads, Macs
	"_airplay._tcp.local.",        // Apple TV, HomePod, televisions
	"_raop._tcp.local.",           // AirPlay audio receivers
	"_googlecast._tcp.local.",     // Chromecast, Android TV, Nest speakers
	"_spotify-connect._tcp.local.",
	"_printer._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_scanner._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_workstation._tcp.local.", // Linux desktops via Avahi
	"_ssh._tcp.local.",
	"_http._tcp.local.",
	"_hap._tcp.local.", // HomeKit accessories
}

// QueryMDNS sends the DNS-SD enumeration query and asks directly for the
// service types a household commonly runs.
//
// Failure is not an error worth surfacing: the listeners still work, discovery is
// simply slower.
func QueryMDNS(ctx context.Context) error {
	questions := make([]dnsmessage.Question, 0, len(commonServices)+1)
	for _, name := range append([]string{dnssdMetaQuery}, commonServices...) {
		n, err := dnsmessage.NewName(name)
		if err != nil {
			return fmt.Errorf("build mDNS query for %q: %w", name, err)
		}
		questions = append(questions, dnsmessage.Question{
			Name:  n,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		})
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			// ID zero and a query message: multicast DNS matches on the question
			// rather than the transaction ID.
			Response: false,
		},
		Questions: questions,
	}
	packed, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("build mDNS query: %w", err)
	}

	// A short-lived sender rather than reusing a listening socket: the listener
	// is bound to the wildcard address for receiving, and sending from a separate
	// socket keeps the two concerns from interfering.
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return fmt.Errorf("open mDNS sender: %w", err)
	}
	defer conn.Close()

	target := &net.UDPAddr{IP: mdnsGroup.AsSlice(), Port: mdnsPort}
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.WriteTo(packed, target); err != nil {
		return fmt.Errorf("send mDNS query: %w", err)
	}
	return nil
}
