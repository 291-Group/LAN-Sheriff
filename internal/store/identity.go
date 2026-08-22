package store

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
)

// How a device is recognised across time.
//
// The hard part of a device roster is not finding devices, it is deciding that
// the thing you are looking at now is the same thing you saw yesterday. Nothing
// observable is both universal and permanent:
//
//   - An IP address is reassigned by DHCP, so it identifies nothing over time.
//     It is deliberately not an identity key here.
//   - A hardware address survives DHCP and reboots, and is the strongest key
//     available, but phones randomize theirs.
//   - A randomized address is still stable *on one network* (see
//     discover.IsRandomized), so it is a real key, just one that can rotate.
//   - A hostname is stable and human-meaningful, but users change it and two
//     devices can claim the same one.
//
// So a device carries a *set* of keys rather than one, and is recognised by any
// of them. When a later observation shows that two keys belong to one machine,
// the two records are merged.

// KeyKind names an identity key's type, which is also its confidence ranking.
type KeyKind string

const (
	// KeyMAC is a manufacturer-assigned hardware address: the strongest key,
	// unchanged by DHCP, reboots or reinstalls.
	KeyMAC KeyKind = "mac"
	// KeyRandomMAC is a randomized hardware address. Stable on this network, but
	// it rotates if the user toggles the setting or the OS re-derives it.
	KeyRandomMAC KeyKind = "rmac"
	// KeyHostname is a device's claimed name. Weaker than an address because it
	// is user-editable and can collide, but it is what re-identifies a device
	// that has rotated its randomized address.
	KeyHostname KeyKind = "host"
)

// rank orders keys by how much they should be trusted when two devices merge.
func (k KeyKind) rank() int {
	switch k {
	case KeyMAC:
		return 3
	case KeyRandomMAC:
		return 2
	case KeyHostname:
		return 1
	}
	return 0
}

// identityKey is one way of recognising a device.
type identityKey struct {
	Kind  KeyKind
	Value string
}

func (k identityKey) String() string { return string(k.Kind) + ":" + k.Value }

// normalizeHostname reduces a claimed name to a comparable form.
//
// mDNS, DHCP and reverse DNS report the same machine as "Living-Room-TV.local",
// "living-room-tv" and "LIVING-ROOM-TV", and treating those as three devices
// would be an obvious defect.
func normalizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(h, ".local")
	h = strings.TrimSuffix(h, ".lan")
	h = strings.TrimSuffix(h, ".home")
	// A trailing "-2" is what an OS appends when a name is already taken on the
	// network, usually after the same machine rejoins before its old
	// registration has expired. Kept as-is rather than stripped: two machines
	// genuinely can be "printer" and "printer-2", and merging those would be
	// worse than leaving them separate.
	return h
}

// newDeviceID mints an opaque identifier for a device.
//
// Opaque and random rather than derived from a MAC address or hostname, for two
// reasons. A derived ID would change whenever the property it was derived from
// changed, which is exactly the instability this whole file exists to absorb.
// And it would put a hardware address into every API response, URL and log line
// that mentions a device, which is a tracking identifier the UI does not need.
func newDeviceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice, and if it did, a device ID is
		// not the place to take the process down.
		return "dev-fallback"
	}
	return hex.EncodeToString(b[:])
}

// sortKeys puts the strongest keys first, so that a merge keeps the record whose
// identity is best established.
func sortKeys(keys []identityKey) {
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].Kind.rank() > keys[j].Kind.rank()
	})
}
