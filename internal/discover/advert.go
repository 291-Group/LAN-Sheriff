package discover

import (
	"net/netip"
	"strings"
	"time"
)

// Advert is what a device said about itself.
//
// mDNS and SSDP carry different fields but answer the same three questions: what
// is this thing called, what kind of thing is it, and what does it offer. They
// are normalized into one type so the Roster does not need to care which
// protocol named a device.
type Advert struct {
	Addr netip.AddrPort
	// Source is "mdns" or "ssdp", kept because the two differ in how much they
	// can be trusted: a name a device publishes about itself is better evidence
	// than one inferred from a service type.
	Source string
	// Hostname is the device's own claimed name, such as "living-room-tv.local".
	Hostname string
	// Name is a human-facing label, such as "Kitchen HomePod".
	Name string
	// Model is a manufacturer model string where one is published.
	Model string
	// Services are the service types advertised, such as "_airplay._tcp".
	Services []string
	// Interface is the local interface the advert arrived on.
	Interface string
	SeenAt    time.Time
}

// trimLocal removes the trailing ".local." that every mDNS name carries, since
// it is on every record and carries no information.
func trimLocal(name string) string {
	n := strings.TrimSuffix(name, ".")
	n = strings.TrimSuffix(n, ".local")
	return n
}

// cleanLabel makes a published name fit to show.
//
// mDNS instance names escape spaces as "\032" and dots as "\.", because the wire
// format is a sequence of labels. Shown unprocessed, a HomePod called "Kitchen
// Speaker" appears as "Kitchen\032Speaker".
func cleanLabel(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return strings.TrimSpace(s)
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			i++
			continue
		}
		// A decimal escape is a backslash and exactly three digits.
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			v := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if v <= 255 {
				sb.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		// Otherwise the backslash escapes the next character literally.
		sb.WriteByte(s[i+1])
		i += 2
	}
	return strings.TrimSpace(sb.String())
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
