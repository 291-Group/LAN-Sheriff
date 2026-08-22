//go:build !patrol

package patrol

import (
	"strings"
	"testing"

	"github.com/291-Group/LAN-Sheriff/internal/buildinfo"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// A binary somebody downloaded must never be told to run a build command.
//
// The case this guards: the portable archive is a release artifact built
// without the patrol tag on purpose, so it takes the same branch a source
// checkout does. Without this test it would tell downloaders to run
// `make patrol`, and on Windows "install Npcap, then: make patrol".
func TestDownloadedBuildIsNeverToldToRunMake(t *testing.T) {
	t.Cleanup(func() { buildinfo.Set("") })

	buildinfo.Set("abc1234") // as a release pipeline sets it
	caps := disabled{}.capabilities(Options{})

	if caps.EnableCmd != "" {
		t.Errorf("a downloaded build offered a build command: %q", caps.EnableCmd)
	}
	for _, bad := range []string{"make ", "apt install", "go build", "rebuild with"} {
		if strings.Contains(strings.ToLower(caps.Hint), bad) {
			t.Errorf("hint tells a downloader to build: %q contains %q", caps.Hint, bad)
		}
	}
	if caps.HintCode != types.HintPatrolPortable {
		t.Errorf("a downloaded build must use its own hint code so the dashboard "+
			"does not translate the developer's advice, got %q", caps.HintCode)
	}
	if !strings.Contains(caps.Hint, "standard download") {
		t.Errorf("hint should point at the download that has capture, got %q", caps.Hint)
	}
}

// And the developer keeps the advice that is actually useful to them.
func TestSourceBuildStillGetsTheBuildCommand(t *testing.T) {
	t.Cleanup(func() { buildinfo.Set("") })

	buildinfo.Set("none") // the compiled-in default, i.e. plain `go build`
	caps := disabled{}.capabilities(Options{})

	if caps.EnableCmd == "" {
		t.Error("a source build should be told how to get capture")
	}
	if !strings.Contains(caps.EnableCmd, "make patrol") {
		t.Errorf("expected the build target, got %q", caps.EnableCmd)
	}
}

// The portable build is published for platforms that get no capture build at
// all, and those readers were told "the standard download for your platform
// includes capture". No such file is ever produced for them.
//
// The pairs below are the release matrix that scripts/release/assemble.sh
// asserts. A platform moving between the columns has to be changed in both,
// and this is the copy a person actually reads.
func TestCapturePublishedMatchesTheReleaseMatrix(t *testing.T) {
	for _, c := range []struct {
		goos, goarch string
		want         bool
	}{
		// Capture archives exist for these.
		{"darwin", "amd64", true},
		{"darwin", "arm64", true},
		{"linux", "amd64", true},
		{"linux", "arm64", true},
		{"windows", "amd64", true},

		// Portable is the only archive published for these, so nothing should
		// point their users at a standard download.
		{"freebsd", "amd64", false},
		{"freebsd", "arm64", false},
		{"linux", "arm", false},
		{"windows", "arm64", false},

		// Anything else is somebody building for themselves.
		{"openbsd", "amd64", false},
		{"netbsd", "arm64", false},
	} {
		if got := CapturePublishedFor(c.goos, c.goarch); got != c.want {
			t.Errorf("CapturePublishedFor(%q, %q) = %v, want %v",
				c.goos, c.goarch, got, c.want)
		}
	}
}
