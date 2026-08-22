package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows, as a real service.
//
// Runs as LocalSystem, which is what gives Npcap the access it needs to open an
// adapter in promiscuous mode. Without it the service starts, works, and sits
// in Deputy Mode, which looks so much like working that nobody notices; that
// exact failure cost this project ten days on a Raspberry Pi.

func serviceSupported() bool { return true }

func serviceManagerName() string { return "the Windows service manager" }

// hasAdmin reports whether this process can create a service. Membership of
// the Administrators group is not the question, because an elevated token is
// what actually matters and an unelevated shell run by an administrator has
// the group without the privilege.
func hasAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

func elevateHint() string {
	return "installing a service needs an Administrator prompt.\n" +
		"  Right-click PowerShell, choose \"Run as administrator\", then run:\n" +
		"    lan-sheriff install"
}

// Program Files, because that is where installed programs go and where the
// default permissions already stop an unprivileged user from replacing a
// binary that LocalSystem is about to execute. Installing to a user-writable
// directory and running it as LocalSystem would be a privilege escalation
// waiting to be found.
func defaultBinPath() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "LAN Sheriff", "lan-sheriff.exe")
}

func defaultServiceDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "LAN Sheriff")
}

func installService(cfg installConfig) ([]step, error) {
	var steps []step

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return steps, fmt.Errorf("creating %s: %w", cfg.DataDir, err)
	}
	steps = append(steps, step{"data", cfg.DataDir})

	m, err := mgr.Connect()
	if err != nil {
		return steps, fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect()

	// Replace an existing install rather than failing on it.
	if existing, err := m.OpenService(serviceName); err == nil {
		_ = stopAndWait(existing)
		_ = existing.Delete()
		existing.Close()
		// The service manager keeps a deleted service around until every
		// handle closes, and creating one with the same name before that
		// happens fails with "marked for deletion".
		time.Sleep(time.Second)
	}

	s, err := m.CreateService(serviceName, cfg.BinPath, mgr.Config{
		DisplayName: "LAN Sheriff",
		Description: "Watches which servers this network talks to. Observes only; blocks nothing.",
		StartType:   mgr.StartAutomatic,
		// LocalSystem: needed for packet capture through Npcap.
		ServiceStartName: "",
	},
		"serve",
		"--listen", cfg.Listen,
		"--data-dir", cfg.DataDir,
		"--open=false",
	)
	if err != nil {
		return steps, fmt.Errorf("creating the service: %w", err)
	}
	defer s.Close()
	steps = append(steps, step{"service", `"LAN Sheriff" (` + serviceName + `)`})
	steps = append(steps, step{"boot", "automatic, starts with the machine"})

	// Restart on failure, twice, then leave it alone. A service that respawns
	// forever on a configuration error just fills the event log.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.NoAction},
	}, 86400); err != nil {
		steps = append(steps, step{"recovery", "could not set restart policy: " + err.Error()})
	}

	if cfg.Start {
		if err := s.Start(); err != nil {
			return steps, fmt.Errorf("starting the service: %w\n"+
				"  check it with: Get-Service %s", err, serviceName)
		}
		steps = append(steps, step{"running", "yes (Get-Service " + serviceName + ")"})
	}

	// **On PATH, which on Windows is a deliberate act.**
	//
	// On Linux and macOS the install directory is already on everybody's PATH,
	// so copying the binary there is the whole job. Windows has no such
	// directory: C:\Program Files\LAN Sheriff is where an installed program
	// belongs and is on nobody's PATH, so `lan-sheriff status` in a terminal
	// answers "not recognised" while the README says it works from any terminal.
	if err := addToSystemPath(filepath.Dir(cfg.BinPath)); err != nil {
		steps = append(steps, step{"PATH", "could not add the folder: " + err.Error()})
	} else {
		steps = append(steps, step{"PATH", filepath.Dir(cfg.BinPath) + " (open a new terminal)"})
	}
	return steps, nil
}

// addToSystemPath appends dir to the machine PATH, once.
//
// Written through the registry rather than with setx, which truncates the value
// at 1024 characters without saying so and has destroyed many a system PATH.
// The value keeps its REG_EXPAND_SZ type, because the existing PATH contains
// entries like %SystemRoot% that stop working the moment it is rewritten as a
// plain string.
func addToSystemPath(dir string) error {
	const key = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	cur, valType, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	for _, part := range strings.Split(cur, ";") {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(part), `\`),
			strings.TrimRight(dir, `\`)) {
			return nil // already there, and adding it twice is its own bug
		}
	}

	updated := strings.TrimRight(cur, ";") + ";" + dir
	if valType == registry.EXPAND_SZ {
		if err := k.SetExpandStringValue("Path", updated); err != nil {
			return err
		}
	} else if err := k.SetStringValue("Path", updated); err != nil {
		return err
	}

	// Tell everything already running that the environment changed. Without
	// this the new entry is invisible until the next sign-in, which reads as
	// the installer not having done it.
	broadcastEnvironmentChange()
	return nil
}

// removeFromSystemPath takes the directory back out, leaving the rest alone.
func removeFromSystemPath(dir string) error {
	const key = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	cur, valType, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	kept := make([]string, 0, 16)
	for _, part := range strings.Split(cur, ";") {
		if strings.EqualFold(strings.TrimRight(strings.TrimSpace(part), `\`),
			strings.TrimRight(dir, `\`)) {
			continue
		}
		if strings.TrimSpace(part) != "" {
			kept = append(kept, part)
		}
	}
	updated := strings.Join(kept, ";")
	if valType == registry.EXPAND_SZ {
		if err := k.SetExpandStringValue("Path", updated); err != nil {
			return err
		}
	} else if err := k.SetStringValue("Path", updated); err != nil {
		return err
	}
	broadcastEnvironmentChange()
	return nil
}

func broadcastEnvironmentChange() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	send := user32.NewProc("SendMessageTimeoutW")
	env, _ := windows.UTF16PtrFromString("Environment")
	const (
		hwndBroadcast   = 0xFFFF
		wmSettingChange = 0x001A
		smtoAbortIfHung = 0x0002
	)
	var result uintptr
	_, _, _ = send.Call(hwndBroadcast, wmSettingChange, 0,
		uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000,
		uintptr(unsafe.Pointer(&result)))
}

func uninstallService(purge bool) ([]step, error) {
	var steps []step

	m, err := mgr.Connect()
	if err != nil {
		return steps, fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		_ = stopAndWait(s)
		steps = append(steps, step{"stopped", "yes"})
		if err := s.Delete(); err == nil {
			steps = append(steps, step{"service", "removed"})
		}
		s.Close()
	} else {
		steps = append(steps, step{"service", "was not installed"})
	}

	bin := defaultBinPath()
	if err := removeFromSystemPath(filepath.Dir(bin)); err == nil {
		steps = append(steps, step{"PATH", "entry removed"})
	}
	if err := os.Remove(bin); err == nil {
		_ = os.Remove(filepath.Dir(bin))
		steps = append(steps, step{"binary", "removed " + bin})
	}

	if purge {
		if err := os.RemoveAll(defaultServiceDataDir()); err != nil {
			return steps, fmt.Errorf("removing %s: %w", defaultServiceDataDir(), err)
		}
		steps = append(steps, step{"data", "deleted " + defaultServiceDataDir()})
	}
	return steps, nil
}

// stopAndWait asks a service to stop and waits for it to actually be gone.
// Deleting a service that is still running leaves it registered until the
// process exits, which is how "install twice in a row" turns into a service
// that exists but cannot be started.
func stopAndWait(s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s to stop", serviceName)
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

func run(name string, args ...string) error {
	return fmt.Errorf("unused on windows: %s %s", name, strings.Join(args, " "))
}

// releaseBinaryLock stops a running service so its executable can be replaced.
//
// Windows holds an open handle to the image of a running process and refuses
// any write to it, so the upgrade path has to stop the service before the copy
// rather than as part of registering the new one. Missing service, nothing to
// do, and that is the fresh-install case.
func releaseBinaryLock() error {
	m, err := mgr.Connect()
	if err != nil {
		return nil // no service manager reachable: let the copy try and report
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed yet
	}
	defer s.Close()

	if err := stopAndWait(s); err != nil {
		return err
	}
	// The handle closes when the process exits, which is not the same moment
	// the service reports stopped.
	time.Sleep(1500 * time.Millisecond)
	return nil
}
