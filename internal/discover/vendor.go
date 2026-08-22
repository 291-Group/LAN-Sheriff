package discover

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

// MAC vendor lookup.
//
// Adapted from LAN Orangutan's scanner package, since the two projects need the
// same answer from the same registry and there is no sense in two
// implementations drifting apart.

// ouiData is the IEEE MAC address registry, compressed, as
// "PREFIX<tab>Organization" lines.
//
// Embedded rather than fetched: a tool that is often run on an isolated network
// must be able to name a manufacturer with no internet access. Roughly 39,000
// entries compress to about 370 KB, which is a fair price for that.
//
//go:embed oui.txt.gz
var ouiData []byte

var (
	ouiOnce    sync.Once
	ouiVendors map[string]string
)

// loadOUI decompresses and indexes the registry on first use.
//
// Lazily, because parsing forty thousand entries costs a few milliseconds and a
// run that never sees a MAC address should never pay for it.
func loadOUI() {
	ouiVendors = make(map[string]string, 40000)

	zr, err := gzip.NewReader(bytes.NewReader(ouiData))
	if err != nil {
		return
	}
	defer zr.Close()

	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		prefix, name, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			ouiVendors[prefix] = name
		}
	}
}

// NormalizeMAC reduces a MAC address to bare uppercase hex, accepting the
// aa:bb:cc, AA-BB-CC and aabbcc forms that different sources produce.
func NormalizeMAC(mac string) string {
	var sb strings.Builder
	sb.Grow(12)
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			sb.WriteRune(r)
		case r >= 'a' && r <= 'f':
			sb.WriteRune(r - 'a' + 'A')
		}
	}
	return sb.String()
}

// Vendor returns the manufacturer registered to a MAC address, or "" when the
// address is empty, malformed, randomized, or in an unregistered range.
//
// An empty result rather than "Unknown": the caller decides how to present an
// absence, and a literal "Unknown" stored in a database is a value that later
// has to be special-cased everywhere.
func Vendor(mac string) string {
	norm := NormalizeMAC(mac)
	if len(norm) < 6 {
		return ""
	}
	// A randomized address belongs to nobody, so looking it up would at best
	// return a coincidental match.
	if IsRandomized(mac) {
		return ""
	}

	ouiOnce.Do(loadOUI)
	return ouiVendors[norm[:6]]
}

// IsRandomized reports whether a MAC address was generated rather than assigned
// to a manufacturer.
//
// Phones and laptops randomize their address to avoid being tracked between
// networks. Two consequences, and it is worth being precise about the second
// because the obvious reading of it is wrong:
//
//  1. There is no vendor to look up. The address belongs to nobody.
//  2. The address is still a usable identity *on this network*. Apple's Private
//     Wi-Fi Address and Android's equivalent derive one address per SSID and keep
//     it, so a phone that has joined this network keeps the same randomized
//     address across reconnections. What it cannot do is correlate that phone to
//     any other network, or to a manufacturer.
//
// So randomization weakens identity rather than destroying it: the address is
// treated as a real key, but a rotatable one, and a device that reappears under a
// new randomized address is re-identified by hostname instead.
func IsRandomized(mac string) bool {
	norm := NormalizeMAC(mac)
	if len(norm) < 2 {
		return false
	}
	// Bit 1 of the first octet is the locally-administered flag.
	return hexByte(norm[0], norm[1])&0x02 != 0
}

func hexByte(hi, lo byte) byte { return hexNibble(hi)<<4 | hexNibble(lo) }

func hexNibble(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return c - 'A' + 10
}
