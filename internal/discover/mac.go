package discover

import (
	"strings"
)

// FormatMAC renders any hardware-address spelling as the colon-separated
// uppercase form people recognise.
//
// Stored rather than normalized hex, because this string is shown to the user;
// identity comparison uses the normalized form held in device_keys, so display
// and matching do not have to agree on a single representation.
func FormatMAC(mac string) string { return formatMAC(NormalizeMAC(mac)) }

// formatMAC renders bare hex as the colon-separated form people recognise.
//
// Stored in this canonical form so that two sources reporting the same device
// produce the same string, and so a MAC shown in the UI is readable.
func formatMAC(norm string) string {
	if len(norm) != 12 {
		return norm
	}
	var sb strings.Builder
	sb.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(norm[i : i+2])
	}
	return sb.String()
}

// interfaceNames maps interface indexes to names, for sources that report only
// an index.
