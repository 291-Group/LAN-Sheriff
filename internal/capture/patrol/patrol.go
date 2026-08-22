// Package patrol implements Patrol Mode: watching the whole network by
// passively capturing packets, rather than only this machine's own sockets.
//
// This is the half of the product that can see devices which cannot run
// software, televisions, thermostats, doorbells, printers. Deputy Mode can
// never see those, and neither can peer sharing, because you cannot install a
// binary on a doorbell. Passive capture at a vantage point is the only route.
//
// # Why this is behind a build tag
//
// Packet capture needs libpcap (Linux, macOS) or Npcap (Windows), which means
// cgo. The default build must stay cgo-free so cross-compiling to a Raspberry Pi
// and `go install` both stay trivial. Everything here is
// therefore compiled only with `-tags patrol`; without it, patrol_disabled.go
// provides the same API and reports the mode unavailable.
//
// # What it needs to be useful
//
// Privilege alone is not enough. On a switched network a machine sees only its
// own traffic plus broadcast, however many capabilities it holds. Seeing the
// network requires a vantage point: running on the gateway, a mirror/SPAN port,
// or at minimum being the device other traffic passes through. The capability
// probe reports privilege; it cannot detect a poor vantage point, so the UI says
// so plainly rather than implying an empty view means an empty network.
package patrol

import (
	"context"
	"runtime"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Options configures the capture source.
type Options struct {
	// Interface is the device to capture on. Empty means choose automatically.
	Interface string

	// SnapshotLen bounds how much of each packet is copied out of the kernel.
	// Headers and a little room for a TLS ClientHello or a DNS answer is all
	// this needs; payloads are never stored, so copying them would be waste.
	SnapshotLen int

	// Promiscuous asks the interface for traffic not addressed to this host.
	// Required to see other devices, and refused on some virtual interfaces.
	Promiscuous bool

	// DeviceID identifies this host, for flows that turn out to be its own.
	DeviceID string
}

// DefaultSnapshotLen is enough for L2/L3/L4 headers plus a DNS response or a
// TLS ClientHello carrying an SNI, and nothing beyond.
const DefaultSnapshotLen = 512

func (o Options) withDefaults() Options {
	if o.SnapshotLen <= 0 {
		o.SnapshotLen = DefaultSnapshotLen
	}
	return o
}

// Available reports whether this build can capture packets at all.
//
// It answers the build question, not the privilege question: a `patrol`-tagged
// binary run without capture rights still returns true here and fails at Start,
// which is where the actionable message belongs.
func Available() bool { return available() }

// Interface describes a capture interface offered to the user.
type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	// Up and Loopback come from the interface flags, and are what makes an
	// automatic choice possible.
	Up       bool `json:"up"`
	Loopback bool `json:"loopback"`
	// Recommended marks the interface automatic selection would pick.
	Recommended bool `json:"recommended"`
}

// Interfaces lists what could be captured on, for the settings UI.
func Interfaces() ([]Interface, error) { return interfaces() }

// ActiveInterface reports the device this source is capturing on, or "" when it
// is not capturing. The automatic choice is otherwise invisible: on Windows the
// device name is a GUID and a wrong pick shows up only as a view that stays
// empty, which is how one went unnoticed on a tester's machine.
func (s *Source) ActiveInterface() string {
	if l, ok := s.impl.(interface{ activeInterface() string }); ok {
		return l.activeInterface()
	}
	return ""
}

// Source is the Patrol Mode capture source. It satisfies capture.Source.
type Source struct {
	opts Options
	impl sourceImpl
}

// sourceImpl is the build-tag-dependent half.
type sourceImpl interface {
	start(ctx context.Context, opts Options, out chan<- types.RawEvent) error
	stop() error
	capabilities(opts Options) types.Capabilities
}

// New builds a Patrol Mode source. Like Deputy Mode it never returns an error:
// an unavailable source reports itself unavailable and explains why, and the
// application carries on with whatever else it has.
func New(opts Options) *Source {
	return &Source{opts: opts.withDefaults(), impl: newImpl()}
}

func (s *Source) Name() string { return "patrol" }

func (s *Source) Capabilities() types.Capabilities { return s.impl.capabilities(s.opts) }

func (s *Source) Start(ctx context.Context, out chan<- types.RawEvent) error {
	return s.impl.start(ctx, s.opts, out)
}

func (s *Source) Stop() error { return s.impl.stop() }

// CapturePublished reports whether a capture build exists for this platform.
//
// The release carries a capture archive for Linux amd64 and arm64, both macOS
// architectures and Windows amd64. Everything else gets the portable archive
// and only that, so pointing those readers at "the standard download" would
// name a file that was never built. Read from the constants the compiler fills
// in, so it cannot drift out of step with the binary it is describing.
//
// Kept beside the message it governs rather than in the release scripts,
// because it is the message that goes wrong when the two disagree.
func CapturePublished() bool {
	return CapturePublishedFor(runtime.GOOS, runtime.GOARCH)
}

// CapturePublishedFor is the part worth testing. Reading runtime.GOOS directly
// would mean the mapping could only ever be exercised on the platform running
// the tests, which is the one platform whose answer nobody needs checked.
//
// The list is the release matrix asserted by scripts/release/assemble.sh. If
// the two ever disagree, this is the one that reaches a person.
func CapturePublishedFor(goos, goarch string) bool {
	switch goos {
	case "darwin":
		return true // both architectures, and no portable archive is published
	case "linux":
		return goarch == "amd64" || goarch == "arm64" // not arm
	case "windows":
		return goarch == "amd64" // not arm64
	}
	return false // freebsd, and anything else somebody builds themselves
}
