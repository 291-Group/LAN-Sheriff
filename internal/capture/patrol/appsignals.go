//go:build patrol

package patrol

import (
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Application-layer signals, parsed for labelling only.
//
// This is the one place in the codebase that looks inside a packet's contents,
// and the boundary is strict: the DNS question and its answers, the TLS server
// name, and the HTTP Host header. Nothing else is read and no payload is ever
// stored. That boundary is the difference between a
// visibility tool and surveillance.
//
// There is no TLS interception. The server name is readable because a
// ClientHello sends it in the clear before encryption begins; everything after
// that is opaque and stays opaque.

// parseDNS extracts a DNS observation from a packet, or nil if there is none.
//
// Both questions and answers are useful: the question says what a device wanted,
// the answers tie a name to the addresses that then appear on the map.
func parseDNS(pkt gopacket.Packet) *types.DNSEvent {
	l := pkt.Layer(layers.LayerTypeDNS)
	if l == nil {
		return nil
	}
	dns, ok := l.(*layers.DNS)
	if !ok || len(dns.Questions) == 0 {
		return nil
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	q := dns.Questions[0]
	ev := &types.DNSEvent{
		TS:    ts,
		QName: normalizeDNSName(string(q.Name)),
		QType: q.Type.String(),
	}
	if ev.QName == "" {
		return nil
	}

	for _, a := range dns.Answers {
		switch {
		case a.IP != nil:
			if addr, ok := netutil.AddrFromIP(a.IP); ok {
				ev.Answers = append(ev.Answers, addr.String())
			}
		case len(a.CNAME) > 0:
			// A CNAME is worth keeping: it is often what reveals that an
			// innocuous-looking name resolves into an ad or telemetry network.
			ev.Answers = append(ev.Answers, normalizeDNSName(string(a.CNAME)))
		}
	}

	// Attribute the query to whoever asked. On a response the asker is the
	// destination, so direction has to be worked out from the DNS header rather
	// than assumed.
	if asker, ok := dnsAsker(pkt, dns); ok {
		ev.DeviceID = deviceIDFor(asker)
	}
	return ev
}

// normalizeDNSName lowercases a name and drops any trailing root dot, so the
// same domain always aggregates to one row regardless of how it was encoded.
func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// dnsAsker returns the address that issued the query.
func dnsAsker(pkt gopacket.Packet, dns *layers.DNS) (string, bool) {
	src, dst, _, ok := endpointsOf(pkt)
	if !ok {
		return "", false
	}
	if dns.QR {
		// A response travels back to the asker.
		return dst.Addr().String(), true
	}
	return src.Addr().String(), true
}

// deviceIDFor gives an internal address a stable identity before device
// discovery has named it. External addresses get nothing: a DNS query arriving
// from outside the network is not one of our devices.
func deviceIDFor(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !netutil.IsInternal(addr) {
		return ""
	}
	self := netutil.Local()
	if self.IP != "" && ip == self.IP {
		return self.DeviceID
	}
	return "lan-" + ip
}

// tlsServerName extracts the SNI from a TLS ClientHello.
//
// Readable in the clear by design: the client must tell the server which
// certificate it wants before a secure channel exists. This reads that one
// field and nothing else.
func tlsServerName(payload []byte) (string, bool) {
	// Record header: type(1) version(2) length(2), then the handshake.
	if len(payload) < 43 || payload[0] != 0x16 {
		return "", false // not a TLS handshake record
	}
	// Handshake header: type(1) length(3). Type 1 is ClientHello.
	hs := payload[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", false
	}

	// Skip: handshake header(4) version(2) random(32) then the session id.
	p := 4 + 2 + 32
	if len(hs) < p+1 {
		return "", false
	}
	p += 1 + int(hs[p]) // session id length, then the id

	// Cipher suites.
	if len(hs) < p+2 {
		return "", false
	}
	p += 2 + int(uint16(hs[p])<<8|uint16(hs[p+1]))

	// Compression methods.
	if len(hs) < p+1 {
		return "", false
	}
	p += 1 + int(hs[p])

	// Extensions.
	if len(hs) < p+2 {
		return "", false
	}
	extEnd := p + 2 + int(uint16(hs[p])<<8|uint16(hs[p+1]))
	p += 2
	if extEnd > len(hs) {
		extEnd = len(hs)
	}

	for p+4 <= extEnd {
		extType := uint16(hs[p])<<8 | uint16(hs[p+1])
		extLen := int(uint16(hs[p+2])<<8 | uint16(hs[p+3]))
		p += 4
		if p+extLen > extEnd {
			return "", false
		}
		// Extension 0 is server_name.
		if extType == 0 {
			return parseSNIExtension(hs[p : p+extLen])
		}
		p += extLen
	}
	return "", false
}

// parseSNIExtension reads the server_name list, which holds a length-prefixed
// list of length-prefixed names, of which only type 0 (host_name) matters.
func parseSNIExtension(ext []byte) (string, bool) {
	if len(ext) < 5 {
		return "", false
	}
	// list length(2), then entries of type(1) length(2) value.
	p := 2
	for p+3 <= len(ext) {
		nameType := ext[p]
		nameLen := int(uint16(ext[p+1])<<8 | uint16(ext[p+2]))
		p += 3
		if p+nameLen > len(ext) {
			return "", false
		}
		if nameType == 0 && nameLen > 0 {
			return strings.ToLower(string(ext[p : p+nameLen])), true
		}
		p += nameLen
	}
	return "", false
}

// httpHost extracts the Host header from a plaintext HTTP request.
//
// Only the header, and only from the first line block: this is a label for an
// unencrypted connection, not a request log.
func httpHost(payload []byte) (string, bool) {
	// Bound the scan: a Host header appears early, and reading further would be
	// reading the request body.
	const maxScan = 1024
	if len(payload) > maxScan {
		payload = payload[:maxScan]
	}
	text := string(payload)
	if !looksLikeHTTPRequest(text) {
		return "", false
	}
	for _, line := range strings.Split(text, "\r\n") {
		if line == "" {
			break // end of headers
		}
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "host") {
			host := strings.TrimSpace(value)
			if h, _, found := strings.Cut(host, ":"); found {
				host = h
			}
			return strings.ToLower(host), host != ""
		}
	}
	return "", false
}

func looksLikeHTTPRequest(text string) bool {
	for _, method := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
		if strings.HasPrefix(text, method) {
			return true
		}
	}
	return false
}
