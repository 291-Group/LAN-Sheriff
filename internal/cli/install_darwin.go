package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// macOS, through launchd.
//
// # A daemon, not an agent
//
// LaunchAgents run as the logged-in user and start at login. That would avoid
// needing root, and it would also mean the monitor stops when you log out and
// never runs on a Mac sitting headless in a cupboard, which is a fair share of
// the machines this is useful on. It would also be stuck in Deputy Mode
// forever: capture on macOS needs root to open /dev/bpf*, with no capability
// system to grant something narrower.
//
// So: a LaunchDaemon, which needs root once at install time and then starts at
// boot whether anyone logs in or not.
//
// # Why not a service account
//
// The Linux side runs as an unprivileged `lan-sheriff` user because ambient
// capabilities let it capture without being root. macOS has no equivalent, so
// an unprivileged account here would buy the isolation and lose the feature.
// Running as root is the honest trade, and the daemon's own hardening is that
// it opens one listening socket on localhost and writes one directory.

const plistPath = "/Library/LaunchDaemons/com.291group.lan-sheriff.plist"

func serviceSupported() bool { return true }

func serviceManagerName() string { return "launchd" }

func hasAdmin() bool { return os.Geteuid() == 0 }

func elevateHint() string {
	return "installing a system service needs root: run it again with sudo\n" +
		"  sudo lan-sheriff install"
}

func defaultBinPath() string { return "/usr/local/bin/lan-sheriff" }

// Under /usr/local/var rather than /Library/Application Support.
//
// Application Support is where a user's own copy of an app keeps its data, and
// a root daemon writing there invites exactly the confusion this should avoid:
// the same product, two data directories, depending on how it was started.
// /usr/local/var is where a locally installed daemon's state belongs.
func defaultServiceDataDir() string { return "/usr/local/var/lan-sheriff" }

func installService(cfg installConfig) ([]step, error) {
	var steps []step

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return steps, fmt.Errorf("creating %s: %w", cfg.DataDir, err)
	}
	steps = append(steps, step{"data", cfg.DataDir + " (0700)"})

	if err := os.WriteFile(plistPath, []byte(launchdPlist(cfg)), 0o644); err != nil {
		return steps, fmt.Errorf("writing %s: %w", plistPath, err)
	}
	// launchd refuses to load a plist that is group- or world-writable, and
	// says so in a way that sends people looking in the wrong place.
	if err := os.Chown(plistPath, 0, 0); err != nil {
		return steps, fmt.Errorf("setting ownership on %s: %w", plistPath, err)
	}
	steps = append(steps, step{"service", plistPath})

	// bootout first so that installing over an existing install replaces it
	// rather than failing with "service already loaded". A missing service
	// makes this fail, which is why the error is ignored.
	_ = exec.Command("launchctl", "bootout", "system/com.291group.lan-sheriff").Run()

	if cfg.Start {
		if err := run("launchctl", "bootstrap", "system", plistPath); err != nil {
			return steps, fmt.Errorf("%w\n  check it with: sudo launchctl print system/com.291group.lan-sheriff", err)
		}
		steps = append(steps, step{"boot", "enabled, starts with the machine"})
		steps = append(steps, step{"running", "yes (sudo launchctl print system/com.291group.lan-sheriff)"})
	} else {
		steps = append(steps, step{"boot", "enabled, starts with the machine (not started now)"})
	}
	return steps, nil
}

func launchdPlist(cfg installConfig) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.291group.lan-sheriff</string>

	<key>ProgramArguments</key>
	<array>
		<string>` + cfg.BinPath + `</string>
		<string>serve</string>
		<string>--listen</string>
		<string>` + cfg.Listen + `</string>
		<string>--data-dir</string>
		<string>` + cfg.DataDir + `</string>
		<string>--open=false</string>
	</array>

	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>

	<!-- Both streams to one file. launchd discards them otherwise, and the
	     first question about a daemon that will not start is always what it
	     said on the way down. -->
	<key>StandardOutPath</key>
	<string>/var/log/lan-sheriff.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/lan-sheriff.log</string>

	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`
}

func uninstallService(purge bool) ([]step, error) {
	var steps []step

	_ = exec.Command("launchctl", "bootout", "system/com.291group.lan-sheriff").Run()
	steps = append(steps, step{"stopped", "yes"})

	if err := os.Remove(plistPath); err == nil {
		steps = append(steps, step{"service", "removed " + plistPath})
	}
	if err := os.Remove(defaultBinPath()); err == nil {
		steps = append(steps, step{"binary", "removed " + defaultBinPath()})
	}

	if purge {
		if err := os.RemoveAll(defaultServiceDataDir()); err != nil {
			return steps, fmt.Errorf("removing %s: %w", defaultServiceDataDir(), err)
		}
		steps = append(steps, step{"data", "deleted " + defaultServiceDataDir()})
	}
	return steps, nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w\n  %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

// releaseBinaryLock has nothing to do here: replacing a running executable is
// ordinary on this platform. Unlinking gives the new copy a new inode and any
// running process keeps the old one until it exits.
func releaseBinaryLock() error { return nil }
