//go:build !patrol

package patrol

import (
	"context"
	"errors"
	"runtime"

	"github.com/291-Group/LAN-Sheriff/internal/buildinfo"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Built reports whether packet capture is compiled into this binary (compiled without -tags patrol).
// A constant rather than a runtime check: it is a property of the build, and
// the dashboard needs to say which of the two programs somebody is holding.
const Built = false

// The Patrol Mode stand-in for a build without the `patrol` tag.
//
// It exists so that nothing outside this package needs to know whether packet
// capture was compiled in. The API is identical; the mode simply reports itself
// unavailable and tells the user how to get it. A default build is cgo-free and
// therefore cannot capture packets at all.

func available() bool { return false }

func interfaces() ([]Interface, error) {
	return nil, errors.New("this build does not include packet capture")
}

type disabled struct{}

func newImpl() sourceImpl { return disabled{} }

func (disabled) start(context.Context, Options, chan<- types.RawEvent) error {
	return errors.New("this build does not include packet capture")
}

func (disabled) stop() error { return nil }

func (disabled) capabilities(Options) types.Capabilities {
	return types.Capabilities{
		Mode:      "patrol",
		Available: false,
		Topology:  "none",
		// **Two audiences, opposite advice.**
		//
		// This used to assume only a developer could ever reach it, and said so
		// in a comment: "official release binaries ship with capture compiled
		// in". The portable archive is a release binary and is built without the
		// tag deliberately, so a downloader was being told to run `make patrol`
		// against a source tree they do not have. On Windows that read "install
		// Npcap, then: make patrol", which is the exact message a downloaded
		// binary must never show.
		//
		// A downloader cannot build anything, so they get no command at all; the
		// dashboard renders the command only when it is non-empty.
		Hint:      notBuiltHint(),
		HintCode:  notBuiltCode(),
		EnableCmd: enableCmd(),
	}
}

// notBuiltHint explains the situation in terms the reader can act on.
func notBuiltHint() string {
	if buildinfo.IsDistributed() {
		if !CapturePublished() {
			return "This is the portable build. No packet capture build is published for this " +
				"platform, so Patrol Mode is not available here and it sees only this machine."
		}
		return "This is the portable build, which trades packet capture for running anywhere. " +
			"It sees only this machine. The standard download for your platform includes capture: " +
			"https://github.com/291-Group/LAN-Sheriff/releases"
	}
	return "This build was compiled without packet capture, so it sees only this machine. " +
		"Release downloads include it; rebuild with capture enabled to get it here."
}

// notBuiltCode distinguishes the three audiences for the dashboard, which
// translates by code rather than by the text above.
func notBuiltCode() string {
	if buildinfo.IsDistributed() {
		if !CapturePublished() {
			return types.HintPatrolPortableOnly
		}
		return types.HintPatrolPortable
	}
	return types.HintPatrolNotBuilt
}

// enableCmd is the command that produces a capable binary, and is empty for a
// binary somebody downloaded, because there is no such command for them.
func enableCmd() string {
	if buildinfo.IsDistributed() {
		return ""
	}
	return buildHint()
}

// buildHint is the one command that produces a capable binary. The dependency
// differs per platform, so naming the wrong one would send people in circles.
func buildHint() string {
	switch runtime.GOOS {
	case "linux":
		return "sudo apt install libpcap-dev && make patrol"
	case "darwin":
		return "make patrol"
	case "windows":
		return "install Npcap, then: make patrol"
	default:
		return "make patrol"
	}
}
