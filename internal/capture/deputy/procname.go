package deputy

import (
	"path/filepath"
	"strings"
)

// procInfo is what a platform sampler manages to learn about the process that
// owns a socket. Both fields are best-effort: a process we may not inspect
// simply arrives without them.
type procInfo struct {
	name string
	path string
}

// Turning an executable path into a name a person recognizes is not as simple
// as taking the filename.
//
// Self-updating tools routinely install their binary under its version number,
// Such a tool lands at ~/.local/share/<tool>/versions/2.1.218, and nvm, pyenv
// and asdf all do something similar. The filename is then "2.1.218", which is
// also what the kernel reports as the process's accounting name, so both of the
// obvious lookups return a number that means nothing in a UI.
//
// When the filename is a bare version, the answer is almost always the nearest
// enclosing directory that names the thing rather than describing the layout.

// genericDirs are path components that describe where something lives rather
// than what it is, so they are skipped when looking for a name.
var genericDirs = map[string]bool{
	"bin": true, "sbin": true, "libexec": true, "exec": true,
	"versions": true, "version": true, "releases": true, "release": true,
	"current": true, "latest": true, "dist": true, "build": true, "target": true,
	"contents": true, "macos": true, "resources": true, "frameworks": true,
	"usr": true, "local": true, "share": true, "lib": true, "lib64": true,
	"opt": true, "var": true, "home": true, "users": true, "applications": true,
}

// looksLikeVersion reports whether a filename is a bare version string such as
// "2.1.218", "v3", or "1.0.0-rc2".
//
// The rule is narrow on purpose: the name must begin with a digit (after an
// optional "v") and must either carry a separator between components or be
// nothing but digits. That admits real versions including pre-release suffixes,
// while leaving genuine program names that merely start with a digit, "7z"
// being the obvious one, alone. Misfiring here renames a real application, so
// it errs toward doing nothing.
func looksLikeVersion(name string) bool {
	s := strings.TrimPrefix(strings.TrimPrefix(name, "v"), "V")
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}

	separated, allDigits := false, true
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
			separated, allDigits = true, false
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			allDigits = false
		default:
			return false
		}
	}
	return separated || allDigits
}

// friendlyName returns the label to show for an executable path.
//
// It walks up only a few levels: beyond that the directories stop describing
// the program and start describing the filesystem, and a wrong name is worse
// than a dull one.
func friendlyName(path string) string {
	if path == "" {
		return ""
	}
	base := filepath.Base(path)
	if !looksLikeVersion(base) {
		return base
	}

	dir := filepath.Dir(path)
	for i := 0; i < 4; i++ {
		// `filepath.Dir` returns its own input once it reaches the root, and what
		// that root *is* differs by platform: "/" on Unix, "\\" or "C:\\" on
		// Windows. Comparing against a literal "/" walked straight past the root
		// on Windows and returned a bare separator as an application name.
		if dir == "." || dir == "" || filepath.Dir(dir) == dir {
			break
		}
		name := filepath.Base(dir)
		if !looksLikeVersion(name) && !genericDirs[strings.ToLower(name)] {
			// A dotted directory such as ".myapp" is the app's own folder;
			// the leading dot is noise to a reader.
			return strings.TrimPrefix(name, ".")
		}
		dir = filepath.Dir(dir)
	}
	return base
}
