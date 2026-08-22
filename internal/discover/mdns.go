package discover

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The mDNS/DNS-SD listener.
//
// On a home network this is the richest naming source there is. Phones, printers,
// televisions, speakers and thermostats all announce themselves on
// 224.0.0.251:5353 without being asked, publishing a hostname, a friendly name,
// a model string and a list of services. That is exactly what turns a Roster row
// from "192.168.68.58, Samsung" into "Living Room TV, Samsung, AirPlay".
//
// Parsing goes through x/net/dns/dnsmessage rather than a hand-rolled decoder:
// mDNS is DNS wire format, including name compression, and reimplementing that
// would be both more code and less correct.

// mDNS group and port, from RFC 6762.
var mdnsGroup = netip.MustParseAddr("224.0.0.251")

const mdnsPort = 5353

// A multicast DNS response can carry many records. 9000 bytes covers the largest
// legal message comfortably without allocating a large buffer per read.
const mdnsBufSize = 9000

// ListenMDNS delivers a normalized Advert for every mDNS announcement seen.
//
// It is passive: nothing is sent. Devices announce on their own schedule, on
// joining the network and periodically after, so a Roster fills in over minutes
// without this putting a single packet on the wire.
func ListenMDNS(ctx context.Context, out func(Advert)) error {
	return listenMulticast(ctx, mdnsGroup, mdnsPort, mdnsBufSize, func(p multicastPacket) {
		for _, ad := range parseMDNS(p) {
			out(ad)
		}
	})
}

// parseMDNS reports what a message says about every device it describes.
//
// Returns a slice rather than one advert because a single packet can describe
// several devices: a host answering for itself and for a printer it shares
// produces records for both, and crediting all of them to the sender is how this
// machine came to be labelled with a printer's name.
func parseMDNS(p multicastPacket) []Advert {
	m, ok := parseMDNSMessage(p.Data)
	if !ok {
		return nil
	}
	return m.adverts(p.From, p.Interface, time.Now())
}

// nextHeader advances to the next record in the given section.
func nextHeader(p *dnsmessage.Parser, section int) (dnsmessage.ResourceHeader, error) {
	switch section {
	case 0:
		return p.AnswerHeader()
	case 1:
		return p.AuthorityHeader()
	default:
		return p.AdditionalHeader()
	}
}

// absorbTXT pulls the few keys worth having out of a TXT record.
//
// TXT records carry arbitrary key/value pairs and most are protocol plumbing.
// The model and friendly-name keys are the ones that identify a device, and they
// differ by vendor, so several spellings are accepted.
func absorbTXT(txt []string, ad *Advert) {
	for _, kv := range txt {
		key, value, found := strings.Cut(kv, "=")
		if !found || value == "" {
			continue
		}
		// A TXT value is as likely to be an identifier as an instance name is:
		// devices publish UUIDs under the same keys they publish names under, and
		// one reached the Roster before this check existed.
		label := cleanLabel(value)
		if looksLikeIdentifier(label) {
			continue
		}
		switch strings.ToLower(key) {
		// "md" is Apple's model key, "model" and "ty" are used by printers and
		// Chromecast-style devices.
		case "md", "model", "am":
			if ad.Model == "" {
				ad.Model = label
			}
		case "ty", "fn", "n":
			if ad.Name == "" {
				ad.Name = label
			}
		}
	}
}

// isMetaQueryName reports whether a record owner is the service-enumeration name.
func isMetaQueryName(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "_services._dns-sd")
}

// serviceType extracts "_airplay._tcp" from a DNS-SD name.
//
// The enumeration meta-service is excluded: it is a query mechanism, not
// something a device offers. Responses to it are handled separately, where the
// PTR target rather than the owner name carries the type.
func serviceType(name string) string {
	if name == "" || isMetaQueryName(name) {
		return ""
	}
	labels := strings.Split(name, ".")
	for i := 0; i+1 < len(labels); i++ {
		if !strings.HasPrefix(labels[i], "_") {
			continue
		}
		if labels[i+1] == "_tcp" || labels[i+1] == "_udp" {
			return labels[i] + "." + labels[i+1]
		}
	}
	return ""
}

// instanceName extracts "Kitchen Speaker" from
// "Kitchen\032Speaker._airplay._tcp".
//
// Not every instance name is meant for people. Apple's device-pairing services
// publish instances such as
//
//	f6:c0:74:00:00:0f@fe80::f4c0:74ff:fe52:9ae-supportsRP-24
//
// which is an identifier, and putting that in the Roster where a device name
// belongs would look broken. Those are rejected rather than shown.
func instanceName(name string) string {
	if name == "" || strings.HasPrefix(name, "_") {
		return "" // a bare service type has no instance
	}
	// Split on the first label that begins a service type, honouring backslash
	// escapes so an instance name containing a dot is not cut in half.
	idx := strings.Index(name, "._")
	if idx <= 0 {
		return ""
	}
	label := cleanLabel(name[:idx])
	if looksLikeIdentifier(label) {
		return ""
	}
	return label
}

// looksLikeIdentifier reports whether a published name is machine plumbing rather
// than something a person chose.
func looksLikeIdentifier(s string) bool {
	if s == "" {
		return true
	}
	// An address-bearing name is never a chosen label.
	if strings.ContainsAny(s, "@") || strings.Contains(s, "::") {
		return true
	}
	if containsMAC(s) {
		return true
	}
	if isUUID(s) {
		return true
	}
	// A long unbroken run of hexadecimal is a UUID or serial number. Names people
	// choose contain spaces, or at least a vowel or two.
	return isLongHex(s)
}

// containsMAC looks for six hex pairs joined by colons or hyphens anywhere in a
// string, which is the shape of a hardware address.
func containsMAC(s string) bool {
	run, pairs := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isHexDigit(s[i]) {
			run++
			continue
		}
		sep := i < len(s) && (s[i] == ':' || s[i] == '-')
		if run == 2 {
			pairs++
		} else if run != 0 {
			pairs = 0
		}
		if !sep {
			if pairs >= 6 {
				return true
			}
			pairs = 0
		}
		run = 0
	}
	return pairs >= 6
}

// isUUID matches the canonical 8-4-4-4-12 form, which devices publish in TXT
// records under the same keys they use for names.
func isUUID(s string) bool {
	groups := []int{8, 4, 4, 4, 12}
	parts := strings.Split(s, "-")
	if len(parts) != len(groups) {
		return false
	}
	for i, p := range parts {
		if len(p) != groups[i] {
			return false
		}
		for j := 0; j < len(p); j++ {
			if !isHexDigit(p[j]) {
				return false
			}
		}
	}
	return true
}

// isLongHex reports whether a string is a single long hexadecimal token, as a
// UUID or serial number is.
func isLongHex(s string) bool {
	stripped := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' {
			return -1
		}
		return r
	}, s)
	if len(stripped) < 12 {
		return false
	}
	for i := 0; i < len(stripped); i++ {
		if !isHexDigit(stripped[i]) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
