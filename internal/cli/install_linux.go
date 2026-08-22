package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// Linux, through systemd, with OpenRC as the fallback.
//
// The unit written here is the one in packaging/systemd/lan-sheriff.service,
// with ExecStart pointed at wherever the binary was installed. It is duplicated
// rather than embedded because the packaged unit is installed by the package
// manager and owned by it: a binary that rewrote that file would be fighting
// dpkg over a file dpkg believes it owns. Same content, different path, no
// argument about who owns what.

const (
	serviceUser = "lan-sheriff"
	unitPath    = "/etc/systemd/system/lan-sheriff.service"
	openrcPath  = "/etc/init.d/lan-sheriff"
)

func serviceSupported() bool { return haveSystemd() || haveOpenRC() }

func serviceManagerName() string {
	switch {
	case haveSystemd():
		return "systemd"
	case haveOpenRC():
		return "OpenRC"
	}
	return "your init system"
}

func haveSystemd() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

func haveOpenRC() bool {
	_, err := exec.LookPath("rc-service")
	return err == nil
}

func hasAdmin() bool { return os.Geteuid() == 0 }

func elevateHint() string {
	return "installing a system service needs root: run it again with sudo\n" +
		"  sudo lan-sheriff install"
}

// /usr/local/bin, not /usr/bin. /usr/bin belongs to the package manager, and a
// binary dropped there by hand is one the next `apt install lan-sheriff` will
// silently overwrite, or refuse to. /usr/local/bin is the directory the
// filesystem hierarchy standard sets aside for exactly this, and it precedes
// /usr/bin on every default PATH we have found.
func defaultBinPath() string { return "/usr/local/bin/lan-sheriff" }

func defaultServiceDataDir() string { return "/var/lib/lan-sheriff" }

func installService(cfg installConfig) ([]step, error) {
	var steps []step

	if err := ensureServiceUser(); err != nil {
		return steps, err
	}
	steps = append(steps, step{"account", serviceUser + " (system account, no login)"})

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return steps, fmt.Errorf("creating %s: %w", cfg.DataDir, err)
	}
	if err := chownToService(cfg.DataDir); err != nil {
		return steps, err
	}
	steps = append(steps, step{"data", cfg.DataDir + " (0700, owned by " + serviceUser + ")"})

	if haveSystemd() {
		more, err := installSystemd(cfg)
		return append(steps, more...), err
	}
	more, err := installOpenRC(cfg)
	return append(steps, more...), err
}

func installSystemd(cfg installConfig) ([]step, error) {
	var steps []step

	if err := os.WriteFile(unitPath, []byte(systemdUnit(cfg)), 0o644); err != nil {
		return steps, fmt.Errorf("writing %s: %w", unitPath, err)
	}
	steps = append(steps, step{"service", unitPath})

	// systemd hands capture privilege to the process through
	// AmbientCapabilities, so the binary must not carry file capabilities of
	// its own. Clearing them is not tidiness: a file with capabilities set
	// cannot be executed at all in a context where those capabilities are
	// outside the bounding set, so a stray setcap from an earlier manual
	// install would make the service fail to start with a message about the
	// executable format.
	if setcap, err := exec.LookPath("setcap"); err == nil {
		_ = exec.Command(setcap, "-r", cfg.BinPath).Run()
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return steps, err
	}
	if err := run("systemctl", "enable", "lan-sheriff.service"); err != nil {
		return steps, err
	}
	steps = append(steps, step{"boot", "enabled, starts with the machine"})

	if cfg.Start {
		if err := run("systemctl", "restart", "lan-sheriff.service"); err != nil {
			return steps, fmt.Errorf("%w\n  check it with: systemctl status lan-sheriff", err)
		}
		steps = append(steps, step{"running", "yes (systemctl status lan-sheriff)"})
	}
	return steps, nil
}

func systemdUnit(cfg installConfig) string {
	return `[Unit]
Description=LAN Sheriff, a self-hosted network monitor
Documentation=https://github.com/291-Group/LAN-Sheriff
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=` + serviceUser + `
Group=` + serviceUser + `

# Capture needs CAP_NET_RAW, and CAP_NET_ADMIN for promiscuous mode. Ambient
# capabilities hand them to the process, so the binary carries none of its own.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes

ExecStart=` + cfg.BinPath + ` serve \
    --listen ` + cfg.Listen + ` \
    --data-dir ` + cfg.DataDir + ` \
    --open=false

Restart=on-failure
RestartSec=5s

# The record of somebody's network lives here and nowhere else, so the service
# gets write access to exactly one directory and read-only everything else.
StateDirectoryMode=0700
ReadWritePaths=` + cfg.DataDir + `

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

# PrivateDevices is off on purpose: capture needs the packet socket, and
# turning it on removes access to it. The rest of the hardening stands.

[Install]
WantedBy=multi-user.target
`
}

// OpenRC has no equivalent of AmbientCapabilities, so there the file has to
// carry the capabilities itself. This is the same split the package's
// postinstall script makes, for the same reason.
func installOpenRC(cfg installConfig) ([]step, error) {
	var steps []step

	script := `#!/sbin/openrc-run
name="lan-sheriff"
description="LAN Sheriff, a self-hosted network monitor"
command="` + cfg.BinPath + `"
command_args="serve --listen ` + cfg.Listen + ` --data-dir ` + cfg.DataDir + ` --open=false"
command_user="` + serviceUser + `:` + serviceUser + `"
command_background=true
pidfile="/run/lan-sheriff.pid"
output_log="/var/log/lan-sheriff.log"
error_log="/var/log/lan-sheriff.log"

depend() {
	need net
}
`
	if err := os.WriteFile(openrcPath, []byte(script), 0o755); err != nil {
		return steps, fmt.Errorf("writing %s: %w", openrcPath, err)
	}
	steps = append(steps, step{"service", openrcPath})

	setcap, err := exec.LookPath("setcap")
	if err != nil {
		steps = append(steps, step{"capture", "setcap not found, this will run in Deputy Mode"})
	} else if err := exec.Command(setcap, "cap_net_raw,cap_net_admin=eip", cfg.BinPath).Run(); err != nil {
		steps = append(steps, step{"capture", "could not grant capture privilege, this will run in Deputy Mode"})
	} else {
		steps = append(steps, step{"capture", "cap_net_raw,cap_net_admin granted"})
	}

	if err := run("rc-update", "add", "lan-sheriff", "default"); err != nil {
		return steps, err
	}
	steps = append(steps, step{"boot", "enabled, starts with the machine"})

	if cfg.Start {
		if err := run("rc-service", "lan-sheriff", "restart"); err != nil {
			return steps, err
		}
		steps = append(steps, step{"running", "yes (rc-service lan-sheriff status)"})
	}
	return steps, nil
}

func uninstallService(purge bool) ([]step, error) {
	var steps []step

	if haveSystemd() {
		_ = run("systemctl", "disable", "--now", "lan-sheriff.service")
		if err := os.Remove(unitPath); err == nil {
			steps = append(steps, step{"service", "removed " + unitPath})
		}
		_ = run("systemctl", "daemon-reload")
	} else if haveOpenRC() {
		_ = run("rc-service", "lan-sheriff", "stop")
		_ = run("rc-update", "del", "lan-sheriff", "default")
		if err := os.Remove(openrcPath); err == nil {
			steps = append(steps, step{"service", "removed " + openrcPath})
		}
	}
	steps = append(steps, step{"stopped", "yes"})

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

// ensureServiceUser creates the unprivileged account the service runs as, if it
// is not already there. useradd on most distributions, adduser on Alpine, and
// the same flags the package's postinstall script uses.
func ensureServiceUser() error {
	if _, err := user.Lookup(serviceUser); err == nil {
		return nil
	}
	if bin, err := exec.LookPath("useradd"); err == nil {
		return exec.Command(bin, "--system", "--no-create-home",
			"--shell", "/usr/sbin/nologin", "--home-dir", defaultServiceDataDir(), serviceUser).Run()
	}
	if bin, err := exec.LookPath("adduser"); err == nil {
		return exec.Command(bin, "-S", "-H", "-D",
			"-h", defaultServiceDataDir(), "-s", "/sbin/nologin", serviceUser).Run()
	}
	return fmt.Errorf("no useradd or adduser found, so the %s account cannot be created", serviceUser)
}

func chownToService(dir string) error {
	u, err := user.Lookup(serviceUser)
	if err != nil {
		return fmt.Errorf("looking up the %s account: %w", serviceUser, err)
	}
	var uid, gid int
	if _, err := fmt.Sscanf(u.Uid, "%d", &uid); err != nil {
		return err
	}
	if _, err := fmt.Sscanf(u.Gid, "%d", &gid); err != nil {
		return err
	}
	return filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

// run executes a command and folds its output into the error, because
// "exit status 1" on its own has never helped anybody.
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
