package discover

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// The SSDP listener.
//
// SSDP is what UPnP devices use to announce themselves, on 239.255.255.250:1900.
// It covers much of what mDNS does not: routers, smart televisions, games
// consoles, media servers and printers that predate or ignore Bonjour. Between
// the two, most of a household is named.
//
// The announcements are HTTP-shaped messages ("NOTIFY * HTTP/1.1"), so the
// headers are parsed with net/http's own reader rather than by splitting strings.

var ssdpGroup = netip.MustParseAddr("239.255.255.250")

const ssdpPort = 1900

// SSDP messages are small; anything larger than this is not a well-formed
// announcement.
const ssdpBufSize = 2048

// ListenSSDP delivers a normalized Advert for every SSDP announcement seen.
//
// Passive, like the mDNS listener: devices send NOTIFY messages on joining the
// network and periodically to refresh their advertised lifetime, so listening
// alone is enough.
func ListenSSDP(ctx context.Context, out func(Advert)) error {
	return listenMulticast(ctx, ssdpGroup, ssdpPort, ssdpBufSize, func(p multicastPacket) {
		if ad, ok := parseSSDP(p); ok {
			out(ad)
		}
	})
}

func parseSSDP(p multicastPacket) (Advert, bool) {
	// Only announcements and search responses describe a device. A search
	// request ("M-SEARCH") describes what someone is looking for, which says
	// nothing about the sender's identity.
	line, _, found := bytes.Cut(p.Data, []byte("\r\n"))
	if !found {
		return Advert{}, false
	}
	start := strings.ToUpper(strings.TrimSpace(string(line)))
	if !strings.HasPrefix(start, "NOTIFY") && !strings.HasPrefix(start, "HTTP/1.1") {
		return Advert{}, false
	}

	headers, err := readSSDPHeaders(p.Data)
	if err != nil {
		return Advert{}, false
	}

	// A byebye announcement means the device is leaving, so recording it as
	// present would be exactly wrong.
	if strings.EqualFold(strings.TrimSpace(headers.Get("NTS")), "ssdp:byebye") {
		return Advert{}, false
	}

	ad := Advert{
		Addr:      p.From,
		Source:    "ssdp",
		Interface: p.Interface,
		SeenAt:    time.Now(),
	}

	// SERVER is a free-form product string, conventionally
	// "OS/version UPnP/1.0 Product/version". The product is the useful part.
	if server := headers.Get("SERVER"); server != "" {
		ad.Model = productFromServer(server)
	}
	// NT on a notification, ST on a search response: both name the device or
	// service type being advertised.
	deviceType := headers.Get("NT")
	if deviceType == "" {
		deviceType = headers.Get("ST")
	}
	if svc := ssdpServiceName(deviceType); svc != "" {
		ad.Services = append(ad.Services, svc)
	} else if hint := deviceTypeFromLocation(headers.Get("LOCATION")); hint != "" {
		// upnp:rootdevice announcements are common and typeless; the description
		// URL usually names the device where the header does not.
		ad.Services = append(ad.Services, hint)
	}

	if ad.Model == "" && len(ad.Services) == 0 {
		return Advert{}, false
	}
	return ad, true
}

// readSSDPHeaders parses the message's headers.
//
// net/http's reader handles header folding and duplicate keys, and canonicalizes
// names, so "Server:" and "SERVER:" arrive at the same place. Devices are
// inconsistent about case, so that matters.
func readSSDPHeaders(data []byte) (http.Header, error) {
	r := bufio.NewReader(bytes.NewReader(data))
	if _, err := r.ReadString('\n'); err != nil { // discard the start line
		return nil, err
	}
	return textprotoHeaders(r)
}

// productFromServer extracts a product name from a SERVER header.
//
// The convention is "OS/version UPnP/1.0 Product/version", but devices honour it
// loosely. A real printer on the test network sends:
//
//	Network Printer Server UPnP/1.0 V3.00.01.23     AUG-16-2018
//
// so the product is the part *before* the UPnP token, it is three words long, and
// what follows is a firmware version and a build date. Splitting on whitespace
// and picking one token gets this wrong in both directions, which is why the
// header is divided at the UPnP marker instead.
func productFromServer(server string) string {
	before, after := splitAtUPnP(server)

	// Prefer the segment before the marker, but not when it is only a generic
	// kernel string: "Linux/9.0 UPnP/1.0 Samsung-TV/1.0" hides the product after
	// the marker, whereas the printer above puts it before.
	if name := meaningfulProduct(before); name != "" {
		return name
	}
	if name := meaningfulProduct(after); name != "" {
		return name
	}
	return ""
}

// splitAtUPnP divides a SERVER header around its "UPnP/x.y" token, which is
// boilerplate present on essentially every device and therefore a reliable
// landmark.
func splitAtUPnP(server string) (before, after string) {
	upper := strings.ToUpper(server)
	i := strings.Index(upper, "UPNP/")
	if i < 0 {
		return server, ""
	}
	before = server[:i]
	rest := server[i:]
	// Skip past the marker and its version number.
	if j := strings.IndexFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' }); j >= 0 {
		after = rest[j:]
	}
	return before, after
}

// meaningfulProduct cleans a segment down to the words that identify a device,
// dropping version numbers, build dates and generic operating-system names.
func meaningfulProduct(seg string) string {
	var keep []string
	for _, tok := range strings.Fields(seg) {
		tok = strings.Trim(tok, ",;")
		if tok == "" {
			continue
		}
		name, _, _ := strings.Cut(tok, "/")
		if name == "" || isGenericOS(name) || looksLikeVersion(name) || looksLikeDate(name) {
			continue
		}
		keep = append(keep, name)
	}
	if len(keep) == 0 {
		return ""
	}
	return cleanLabel(strings.Join(keep, " "))
}

// isGenericOS reports whether a token names an operating system rather than a
// product. Most devices lead with a kernel string, and "Linux" tells the user
// nothing about what is sitting on their network.
func isGenericOS(name string) bool {
	switch strings.ToLower(name) {
	case "linux", "unix", "windows", "darwin", "posix", "os", "microsoft-windows", "freebsd":
		return true
	// Windows' UPnP Device Host announces itself on every machine that has it
	// enabled. It names a Windows service, not a device, and reporting it as a
	// model told the user nothing.
	case "upnp-device-host", "udhisapi", "microsoft-windows-nt", "ms-device-host":
		return true
	}
	return false
}

// looksLikeVersion matches "1.0", "V3.00.01.23" and similar: a token carrying no
// information about what the device is.
func looksLikeVersion(tok string) bool {
	t := strings.TrimLeft(tok, "vV")
	if t == "" {
		return false
	}
	digits := false
	for i := 0; i < len(t); i++ {
		switch {
		case isDigit(t[i]):
			digits = true
		case t[i] == '.' || t[i] == '-' || t[i] == '_':
		default:
			return false
		}
	}
	return digits
}

// looksLikeDate matches build stamps such as "AUG-16-2018", which a device sends
// as part of its firmware identity and which would otherwise be shown to the user
// as the model name.
func looksLikeDate(tok string) bool {
	t := strings.ToUpper(tok)
	for _, m := range months {
		if !strings.HasPrefix(t, m) {
			continue
		}
		// The month must end the token or be followed by a separator or digit.
		// A bare prefix test would discard real products: "Marantz" begins with
		// MAR, "Octopus" with OCT and "Decoder" with DEC.
		rest := t[len(m):]
		if rest == "" || !isAlpha(rest[0]) {
			return true
		}
	}
	// A bare four-digit year range, as in "2018-08-16".
	return strings.Count(t, "-") >= 2 && strings.IndexFunc(t, func(r rune) bool {
		return r >= 'A' && r <= 'Z'
	}) < 0
}

func isAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

var months = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}

// deviceTypeFromLocation reads the device-description URL for a type hint.
//
// The printer on the test network advertises upnp:rootdevice, which says nothing,
// but its LOCATION is ".../Printer.xml". Vendors name that file after the device,
// so the path is often the only type information in the whole announcement.
func deviceTypeFromLocation(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	base := path.Base(u.Path)
	base = strings.TrimSuffix(base, path.Ext(base))
	// Reject the generic filenames that carry no meaning.
	switch strings.ToLower(base) {
	case "", ".", "/", "description", "desc", "device", "rootdesc", "root", "upnp", "igd", "gatedesc", "xml", "ssdp":
		return ""
	}
	if isGenericOS(base) {
		return ""
	}
	if looksLikeVersion(base) || len(base) > 32 {
		return ""
	}
	return cleanLabel(base)
}

// ssdpServiceName turns a URN such as
// "urn:schemas-upnp-org:device:MediaRenderer:1" into "MediaRenderer".
//
// The root-device and UUID announcements carry no type information, so they
// produce nothing rather than a meaningless label.
func ssdpServiceName(nt string) string {
	nt = strings.TrimSpace(nt)
	if nt == "" || strings.HasPrefix(nt, "uuid:") || nt == "upnp:rootdevice" {
		return ""
	}
	if !strings.HasPrefix(nt, "urn:") {
		return ""
	}
	parts := strings.Split(nt, ":")
	// The trailing field is a version number, so the type is the one before it.
	if len(parts) >= 2 {
		if last := parts[len(parts)-1]; len(last) > 0 && isDigit(last[0]) {
			return cleanLabel(parts[len(parts)-2])
		}
		return cleanLabel(parts[len(parts)-1])
	}
	return ""
}
