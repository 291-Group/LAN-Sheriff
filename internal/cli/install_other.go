//go:build !linux && !darwin && !windows

package cli

import "errors"

// FreeBSD and anything else. The binaries exist for these and work; what does
// not exist is a service definition anybody has tested, and shipping an
// untested rc.d script that writes to /etc is worse than saying so.
func serviceSupported() bool { return false }

func serviceManagerName() string { return "your init system" }

func hasAdmin() bool { return false }

func elevateHint() string { return "not supported on this platform" }

func defaultBinPath() string { return "/usr/local/bin/lan-sheriff" }

func defaultServiceDataDir() string { return "/var/db/lan-sheriff" }

func installService(installConfig) ([]step, error) {
	return nil, errors.New("no supported service manager")
}

func uninstallService(bool) ([]step, error) {
	return nil, errors.New("no supported service manager")
}

// releaseBinaryLock has nothing to do here: replacing a running executable is
// ordinary on this platform. Unlinking gives the new copy a new inode and any
// running process keeps the old one until it exits.
func releaseBinaryLock() error { return nil }
