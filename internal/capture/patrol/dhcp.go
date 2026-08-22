//go:build patrol

package patrol

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Reading DHCP.
//
// A device asking for an address says more about itself in that one exchange
// than in hours of ordinary traffic. It gives its own name, often its vendor,
// and (in the order it requests options) a signature characteristic of its
// operating system.
//
// This is Patrol Mode only, and unavoidably so: DHCP is broadcast to a
// privileged port, and the only unprivileged way to bind it is to be the DHCP
// client, which this is not.
//
// **On the fingerprint.** The parameter request list is genuinely
// discriminating, and a large curated database of them exists. This uses a short
// list covering broad families, and reports what it finds as a hint rather than
// a fact. Claiming "iOS 17.4" from a signature nobody here has verified would be
// the kind of confident wrongness that teaches people to distrust the whole
// product.

// parseDHCP extracts what a DHCP message says about the device that sent it.
//
// Returns nil for anything that is not a client message: a server's reply
// describes the server's opinion of the client, not the client's own account of
// itself.
func parseDHCP(pkt gopacket.Packet) *types.Sighting {
	layer := pkt.Layer(layers.LayerTypeDHCPv4)
	if layer == nil {
		return nil
	}
	dhcp, ok := layer.(*layers.DHCPv4)
	if !ok || dhcp.Operation != layers.DHCPOpRequest {
		return nil
	}

	sighting := &types.Sighting{Source: "dhcp"}

	if len(dhcp.ClientHWAddr) == 6 {
		sighting.MAC = dhcp.ClientHWAddr.String()
	}
	// ClientIP is set on renewal; on a first request the device has no address
	// yet, and the sighting is keyed on the hardware address alone.
	if ip := dhcp.ClientIP.String(); ip != "" && ip != "0.0.0.0" {
		sighting.IP = ip
	}

	var params []byte
	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptHostname:
			if name := cleanDHCPText(opt.Data); name != "" {
				sighting.Hostname = name
			}
		case layers.DHCPOptClassID:
			// The vendor class is free text the device chose, such as
			// "android-dhcp-14" or "MSFT 5.0". Useful, and often more specific
			// than the fingerprint.
			if class := cleanDHCPText(opt.Data); class != "" {
				sighting.Model = class
			}
		case layers.DHCPOptParamsRequest:
			params = opt.Data
		}
	}

	if os := fingerprintOS(params, sighting.Model); os != "" {
		sighting.Services = append(sighting.Services, "os:"+os)
	}

	// A message that identified nothing is not worth reporting.
	if sighting.MAC == "" && sighting.Hostname == "" {
		return nil
	}
	return sighting
}

// cleanDHCPText makes an option's bytes fit to store.
//
// DHCP strings are not required to be terminated or to be valid UTF-8, and a
// device with firmware written in a hurry will send whatever is in the buffer.
func cleanDHCPText(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return ""
	}
	for _, r := range s {
		// Control characters mean the field is not text.
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return s
}

// fingerprintOS names an operating system family from the parameter request
// list, or from the vendor class where that is decisive.
//
// Deliberately coarse. The families below are the ones whose signatures are
// stable and widely documented; anything narrower would be a guess wearing a
// version number.
func fingerprintOS(params []byte, vendorClass string) string {
	// The vendor class, where present, is the device's own statement and beats
	// any inference from option ordering.
	switch lower := strings.ToLower(vendorClass); {
	case strings.HasPrefix(lower, "android-dhcp"):
		return "Android"
	case strings.HasPrefix(lower, "msft"):
		return "Windows"
	case strings.Contains(lower, "dhcpcd"):
		return "Linux"
	case strings.Contains(lower, "udhcp"):
		return "Embedded Linux"
	}

	if len(params) == 0 {
		return ""
	}
	sig := signature(params)
	return knownFingerprints[sig]
}

// signature renders a parameter request list as a comparable string. Order
// matters and is the point: the same options requested in a different order are
// a different implementation.
func signature(params []byte) string {
	var sb strings.Builder
	for i, p := range params {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(p)))
	}
	return sb.String()
}

// knownFingerprints maps parameter request lists to an operating system family.
//
// Short on purpose. Each entry is a family whose request list is stable across
// versions and widely reported; the list is not trying to be Fingerbank.
var knownFingerprints = map[string]string{
	// Apple's list is distinctive and shared across iOS and macOS.
	"1,121,3,6,15,119,252":          "Apple",
	"1,121,3,6,15,119,252,95,44,46": "Apple",
	// Windows.
	"1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows",
	"1,15,3,6,44,46,47,31,33,121,249,43":         "Windows",
	// Common Linux clients.
	"1,28,2,3,15,6,119,12,44,47,26,121,42": "Linux",
	"1,3,6,12,15,26,28,51,58,59,43":        "Linux",
	// Printers and small embedded stacks tend to ask for very little.
	"1,3,6,15": "Embedded",
}
