// Package types holds the unified event model that every capture source
// normalizes into, so that nothing downstream of the normalizer has to care
// where an observation came from.
package types

import (
	"fmt"
	"net/netip"
	"time"
)

// Proto is a transport protocol.
type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoICMP Proto = "icmp"
)

// Conn is a single observed connection, as reported by a capture source. It is
// deliberately flat: sources fill in what they can see and leave the rest zero.
// Deputy Mode fills Process/PID but usually not the byte counters; Patrol Mode
// is the other way round.
type Conn struct {
	Src   netip.AddrPort
	Dst   netip.AddrPort
	Proto Proto

	// State is the transport state where the source exposes one ("ESTABLISHED",
	// "SYN_SENT", ...). Empty for connectionless observations.
	State string

	// DeviceID is the device this connection originated from. In Deputy Mode
	// that is always the local host.
	DeviceID string

	PID         int32
	Process     string // short name, e.g. "Google Chrome"
	ProcessPath string // full executable path, when the OS will tell us

	BytesOut uint64
	BytesIn  uint64

	// Listening marks a socket that is accepting connections rather than being
	// one. These are not flows, but they tell the normalizer which local ports
	// are servers, which is how inbound connections are recognized.
	Listening bool
}

// Direction records who opened a connection. This is not cosmetic: an inbound
// connection is a fundamentally different event from an outbound one, and
// showing them the same way would be actively misleading.
type Direction string

const (
	// DirOut is a connection this network opened to the outside.
	DirOut Direction = "out"
	// DirIn is a connection something outside opened to us, an exposed
	// service, a port-forward, or something that should not be reachable.
	DirIn Direction = "in"
	// DirInternal is a connection that never leaves the local network.
	DirInternal Direction = "internal"
)

// FlowKey identifies a flow. Two observations with the same key are the same
// flow. The local port is part of the key: a browser opening six connections to
// the same host is six flows, which is what makes beaconing detectable later.
type FlowKey struct {
	Src      netip.AddrPort
	Dst      netip.AddrPort
	Proto    Proto
	DeviceID string
}

// Key returns the flow key for this connection.
func (c Conn) Key() FlowKey {
	return FlowKey{Src: c.Src, Dst: c.Dst, Proto: c.Proto, DeviceID: c.DeviceID}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s|%s->%s", k.Proto, k.Src, k.Dst)
}

// Flow is a connection tracked over time by the normalizer.
type Flow struct {
	ID       int64     `json:"id"`
	Key      FlowKey   `json:"-"`
	TSStart  time.Time `json:"ts_start"`
	TSLast   time.Time `json:"ts_last"`
	DeviceID string    `json:"device_id,omitempty"`
	Process  string    `json:"process,omitempty"`
	PID      int32     `json:"pid,omitempty"`

	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	Proto   Proto  `json:"proto"`

	BytesOut  uint64    `json:"bytes_out"`
	BytesIn   uint64    `json:"bytes_in"`
	Direction Direction `json:"direction"`
	Suspicion float64   `json:"suspicion"`

	// Active reports whether the flow was still open at TSLast.
	Active bool `json:"active"`
	// Established reports whether this connection ever reached a state in which
	// data could flow.
	//
	// A socket still connecting, or one that was refused, is not evidence that
	// anything is listening on the other end, a distinction that matters
	// because the on-demand port check knocks on doors that do not open, and
	// those knocks are visible to the socket sampler like any other connection.
	Established bool `json:"established,omitempty"`
}

// Endpoint is a remote (or local) IP with its cached enrichment.
type Endpoint struct {
	IP          string     `json:"ip"`
	RDNS        string     `json:"rdns,omitempty"`
	ASN         int        `json:"asn,omitempty"`
	Org         string     `json:"org,omitempty"`
	Country     string     `json:"country,omitempty"` // ISO 3166-1 alpha-2
	CountryName string     `json:"country_name,omitempty"`
	City        string     `json:"city,omitempty"`
	Lat         float64    `json:"lat,omitempty"`
	Lon         float64    `json:"lon,omitempty"`
	IsInternal  bool       `json:"is_internal"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	EnrichedAt  *time.Time `json:"enriched_at,omitempty"`
}

// Located reports whether this endpoint can be drawn on the map.
func (e Endpoint) Located() bool { return e.Lat != 0 || e.Lon != 0 }

// Trust levels for a device.
const (
	TrustUnknown   = "unknown"
	TrustDeputized = "deputized"
	TrustWatched   = "watched"
)

// Device is a machine on the network, or this host in Deputy Mode.
type Device struct {
	ID         string    `json:"id"`
	MAC        string    `json:"mac,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	DeviceType string    `json:"device_type,omitempty"`
	Label      string    `json:"label,omitempty"`
	Trust      string    `json:"trust"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Online     bool      `json:"online"`
	Suspicion  float64   `json:"suspicion"`
	IsSelf     bool      `json:"is_self"`
	// Name is what the device calls itself; Label is what the user called it.
	// Kept apart so discovery can never overwrite a name a person chose.
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
	// MACRandomized marks a device whose hardware address is generated. It is
	// still a usable identity on this network, but it can rotate, so the UI says
	// so rather than presenting it as a permanent address.
	MACRandomized bool            `json:"mac_randomized,omitempty"`
	Addresses     []DeviceAddress `json:"addresses,omitempty"`
	Services      []DeviceService `json:"services,omitempty"`
	Notes         string          `json:"notes,omitempty"`
	// TypeReason names the evidence behind DeviceType, as a stable code the
	// dashboard translates. Carried so the UI can explain a classification
	// instead of asking the user to trust it.
	TypeReason string `json:"type_reason,omitempty"`
	// TypeLocked marks a type the user set by hand. Re-inference skips these.
	TypeLocked bool `json:"type_locked,omitempty"`
}

// Sighting is one observation of a device, from any discovery source.
//
// Sources report different subsets: the neighbour table gives an address pair and
// nothing else, an mDNS advert gives a name and services but no hardware address,
// and a DHCP request gives a hostname and a fingerprint. They share one type so
// the identity and merge logic lives in exactly one place.
type Sighting struct {
	MAC      string
	IP       string
	Hostname string
	// Name is a friendly name the device advertised, kept apart from the user's
	// own label so discovery can never overwrite a name a person chose.
	Name     string
	Model    string
	Vendor   string
	Services []string
	IsSelf   bool
	// Source names the discovery mechanism, recorded against services so the UI
	// can say how something was learned.
	Source string
	SeenAt time.Time
	// PreferredID is used as the device ID if this sighting creates a new
	// device, and ignored if it matches an existing one.
	//
	// It exists for this machine. The capture pipeline tags every flow with a
	// device ID derived from the local hardware address, and it must be able to
	// compute that ID before the database is open. Letting the sighting carry it
	// means discovery and capture agree on one record instead of each creating
	// their own.
	PreferredID string
}

// DeviceAddress is one address a device has held. A device has several at once
// (IPv4 and IPv6) and different ones over time (DHCP), so the current address is
// not enough to attribute historical traffic.
type DeviceAddress struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DeviceService is something a device advertises, such as "_airplay._tcp".
type DeviceService struct {
	Service string `json:"service"`
	// Source names how it was learned: "mdns", "ssdp" or "scan".
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DNSEvent is one observed DNS lookup.
type DNSEvent struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	DeviceID string    `json:"device_id,omitempty"`
	Process  string    `json:"process,omitempty"`
	QName    string    `json:"qname"`
	QType    string    `json:"qtype,omitempty"`
	Answers  []string  `json:"answers,omitempty"`
	RespMS   int       `json:"resp_ms,omitempty"`
	Flagged  string    `json:"flagged,omitempty"`
}

// EventKind discriminates the payload carried by a RawEvent.
type EventKind string

const (
	// KindConnSnapshot carries the complete set of connections a polling source
	// can currently see. The normalizer diffs consecutive snapshots to derive
	// flow open and close events.
	KindConnSnapshot EventKind = "conn_snapshot"
	// KindConnDelta carries an incremental observation from a streaming source
	// (Patrol Mode), which knows about a flow without knowing the whole set.
	KindConnDelta EventKind = "conn_delta"
	KindDNS       EventKind = "dns"
	// KindSighting carries identity a capture source learned about a device, as
	// opposed to traffic it observed. DHCP produces these: a device asking for
	// an address states its own name, and often its vendor.
	KindSighting EventKind = "sighting"
	KindDevice   EventKind = "device"
)

// RawEvent is what a capture Source emits.
type RawEvent struct {
	Kind   EventKind
	Source string
	TS     time.Time

	Snapshot []Conn    // KindConnSnapshot
	Conn     *Conn     // KindConnDelta
	DNS      *DNSEvent // KindDNS
	Device   *Device   // KindDevice
	// Sighting carries identity a capture source learned about a device, as
	// distinct from traffic it observed. DHCP is the source of these: a device
	// asking for an address states its own name and often its vendor.
	Sighting *Sighting // KindSighting
}

// Capabilities describes what a source can actually observe here, on this OS,
// at this privilege level. The UI is driven entirely from this so that a
// limited view can always explain itself instead of rendering blank.
type Capabilities struct {
	Mode string `json:"mode"` // "deputy" | "patrol"

	// Available reports whether the source can run at all right now.
	Available bool `json:"available"`

	HostEgress         bool `json:"host_egress"`
	OtherDevices       bool `json:"other_devices"`
	ProcessAttribution bool `json:"process_attribution"`
	ByteCounts         bool `json:"byte_counts"`
	DNSFeed            bool `json:"dns_feed"`
	DeviceInventory    bool `json:"device_inventory"`

	// Topology is how much of the network graph this source can draw:
	// "none", "host" (this host and its peers) or "lan" (everything).
	Topology string `json:"topology"`

	// Hint is the single sentence explaining what is missing and what enabling
	// more would add. Empty when nothing is missing.
	//
	// This is English prose, for API consumers reading the JSON directly. The
	// dashboard does not display it: it displays the translation of HintCode.
	Hint string `json:"hint,omitempty"`

	// HintCode identifies the hint so the UI can translate it.
	//
	// Backend-generated prose cannot be localized, the server has no idea what
	// language the viewer reads, so anything destined for a human travels as a
	// stable code and is rendered on the client.
	HintCode string `json:"hint_code,omitempty"`

	// EnableCmd is the one command that would unlock this source, when it is
	// unavailable for want of privilege.
	EnableCmd string `json:"enable_cmd,omitempty"`
}

// Platform describes the binary and the machine it is running on, so the Help
// page can tell somebody what they are holding instead of listing every
// possibility and leaving them to work out which paragraph is theirs.
//
// It exists because the dashboard could not answer the first question a reader
// asks, which is "does this apply to me". Help had per-platform instructions
// for five platforms and no idea which one it was being read on, so it read
// like documentation rather than like an answer, and the reader went to the
// repository to find out, which is the trip this is meant to remove.
type Platform struct {
	OS      string `json:"os"`   // runtime.GOOS
	Arch    string `json:"arch"` // runtime.GOARCH
	Version string `json:"version"`
	Build   string `json:"build"` // commits reachable from this build

	// CaptureBuilt reports whether packet capture is compiled in. This is the
	// difference between the standard and portable downloads, and it is not
	// inferable from the platform: both are published for most of them.
	CaptureBuilt bool `json:"capture_built"`

	// CapturePublished reports whether a capture build exists for this
	// platform at all. False for FreeBSD, 32-bit ARM and Windows on ARM, where
	// telling somebody to download the standard build would name a file that
	// was never built.
	CapturePublished bool `json:"capture_published"`

	// Distributed reports whether this binary was released rather than built
	// from a source tree. It decides whether advice may name `make`.
	Distributed bool `json:"distributed"`

	DataDir string `json:"data_dir"`
	DBPath  string `json:"db_path"`
}
