// Package buildinfo answers one question: is this binary something we shipped,
// or something a developer just built?
//
// The two audiences need opposite advice. A build without packet capture can
// only usefully tell a developer to `make patrol`, and it must never tell a
// downloader that: the **portable** archive is a shipped release artifact built
// without the tag on purpose, and its reader has no source tree to run a
// Makefile target in. On Windows that advice reads "install Npcap, then: make
// patrol", which is precisely the message a downloaded binary must never show.
//
// # How it knows
//
// The release injects version, commit and date with -ldflags. A plain
// `go build` cannot, so it gets the defaults, and Commit stays "none". That is
// the signal. It is not a guess about intent, it is the presence or absence of
// something only a release pipeline does.
//
// The values are pushed in from the cli package rather than being the ldflags
// target themselves, so the Makefile, goreleaser, the Dockerfile and the
// release workflow all keep pointing where they already point. One less way for
// four build paths to disagree.
package buildinfo

import "sync/atomic"

// distributed is set once at startup. Atomic because capabilities are read from
// HTTP handlers while the process is running, and a plain bool written at
// startup and read from another goroutine is a data race however benign it
// looks.
var distributed atomic.Bool

// Set records how this binary was produced. Called once, early, by the command
// that owns the ldflags variables.
//
// A commit of "none" or an empty string is the compiled-in default, which means
// nothing overrode it, which means no release pipeline touched this binary.
func Set(commit string) {
	distributed.Store(commit != "" && commit != "none")
}

// IsDistributed reports whether this binary came from a release pipeline.
//
// False for `go build`, `go run` and `go test`, which is the safe direction:
// the worst case is telling a developer to download something, and the case
// that matters is never telling a downloader to run a build command.
func IsDistributed() bool { return distributed.Load() }
