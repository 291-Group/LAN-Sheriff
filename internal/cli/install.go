// Installing LAN Sheriff as a service, from the binary itself.
//
// # Why this exists when the packages already do it
//
// The .deb, .rpm and .apk have carried a systemd unit and a service account
// since M5. They cover Linux users who install from a package, and they cover
// them well. They do not cover the person who downloaded a binary from the
// releases page, or copied one off a test card, which is everybody on macOS and
// Windows and a good share of Linux besides. That person had a working
// dashboard for exactly as long as their terminal stayed open, and no obvious
// way to get from there to something that survives a reboot.
//
// Without it, the realistic outcomes are a process tied to an interactive
// session that dies on disconnect, or a hand-typed command line that a reboot
// replaces with a different one. Neither is an install in any sense a user
// would recognise.
//
// # What it deliberately does not do
//
// It does not invent a second set of conventions. The service account, the data
// directory, its 0700 mode, capabilities rather than root, localhost by default,
// and a password the moment it is exposed: all of that is what the packages
// already do, and this reproduces it rather than improving on it. Two installers
// that disagree about where the data lives is worse than either.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/291-Group/LAN-Sheriff/internal/config"
)

// installConfig is what the user asked for, after defaults are filled in.
type installConfig struct {
	// Listen is the address the service will serve the dashboard on.
	//
	// Defaults to localhost. This is the one setting most likely to be wrong
	// for somebody putting this on a headless box, and the only one that is
	// safe to choose on their behalf: an installer that opened a network
	// listener by default would be making that decision for every machine it
	// ever ran on, silently, at root.
	Listen string

	// DataDir is where the database lives.
	DataDir string

	// BinPath is where the executable is installed to.
	BinPath string

	// Start says whether to start the service once it is installed.
	Start bool
}

// step is one thing the installer did, for the summary at the end. Collected
// rather than printed as it goes, so a failure half way through can say what
// had already happened before it stopped.
type step struct {
	what string
	note string
}

func installCmd() *cobra.Command {
	var (
		listen  string
		dataDir string
		noStart bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install as a service that starts at boot",
		Long: fmt.Sprintf(`Install LAN Sheriff so that it runs on its own and survives a reboot.

This copies the binary somewhere on PATH, so 'lan-sheriff' works from any
terminal, registers it with %s, and starts it.

The dashboard listens on localhost only. Pass --listen to reach it from other
machines; it will then refuse to show anything until a password is set.`,
			serviceManagerName()),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := installConfig{
				Listen:  listen,
				DataDir: dataDir,
				BinPath: defaultBinPath(),
				Start:   !noStart,
			}
			if cfg.Listen == "" {
				cfg.Listen = fmt.Sprintf("127.0.0.1:%d", config.DefaultPort)
			}
			if cfg.DataDir == "" {
				cfg.DataDir = defaultServiceDataDir()
			}
			return runInstall(cmd, cfg)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", "",
		fmt.Sprintf("address to serve the dashboard on (default 127.0.0.1:%d)", config.DefaultPort))
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "where to keep the database (default "+defaultServiceDataDir()+")")
	cmd.Flags().BoolVar(&noStart, "no-start", false, "install without starting it")
	return cmd
}

func uninstallCmd() *cobra.Command {
	var purge bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop the service and remove it",
		Long: `Stop LAN Sheriff, remove its service registration, and delete the installed
binary.

The database is left alone unless --purge is given, because the record of a
network is not something to delete as a side effect of uninstalling the thing
that collected it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd, purge)
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete the database and everything in the data directory")
	return cmd
}

func runInstall(cmd *cobra.Command, cfg installConfig) error {
	out := cmd.OutOrStdout()

	if !serviceSupported() {
		return fmt.Errorf("no service manager is supported on %s yet; run it under your own supervisor, "+
			"or start it from a terminal with: lan-sheriff serve", runtime.GOOS)
	}
	if !hasAdmin() {
		return errors.New(elevateHint())
	}

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find the running binary: %w", err)
	}
	// A symlink here would install the link's target under the link's name,
	// which is confusing at best.
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}

	var steps []step

	// **Anything holding the old binary has to let go first.**
	//
	// Windows refuses to replace a running executable, and the thing running it
	// is the service being upgraded, so `install` over an existing install died
	// with "Access is denied" while reporting the service as healthy. Found by
	// upgrading rather than by installing fresh, which is the case every user
	// after the first one is in. A no-op on Linux and macOS, where replacing an
	// open file is ordinary.
	if err := releaseBinaryLock(); err != nil {
		return fmt.Errorf("stopping the existing service so its binary can be replaced: %w", err)
	}

	// Copying before anything else, because it is the step most likely to fail
	// for a boring reason (no space, no permission, read-only mount) and the
	// least trouble to have failed: nothing is registered yet.
	if same, err := sameFile(src, cfg.BinPath); err != nil {
		return err
	} else if same {
		steps = append(steps, step{"binary", cfg.BinPath + " (already in place)"})
	} else {
		if err := installBinary(src, cfg.BinPath); err != nil {
			return fmt.Errorf("copying the binary to %s: %w", cfg.BinPath, err)
		}
		steps = append(steps, step{"binary", cfg.BinPath})
	}

	more, err := installService(cfg)
	steps = append(steps, more...)
	if err != nil {
		printSteps(out, steps)
		return err
	}

	printSteps(out, steps)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Dashboard   %s\n", dashboardURL(cfg.Listen))
	if strings.HasPrefix(cfg.Listen, "127.0.0.1") || strings.HasPrefix(cfg.Listen, "localhost") {
		fmt.Fprintln(out, "              reachable from this machine only")
	} else {
		fmt.Fprintln(out, "              reachable from your network, so it will ask for a password first")
	}
	fmt.Fprintf(out, "  Data        %s\n", cfg.DataDir)
	fmt.Fprintln(out)
	// **With --data-dir, because the service does not use the default one.**
	//
	// A service keeps its database somewhere the whole machine can reach:
	// /var/lib, /usr/local/var, C:\ProgramData. The command line defaults to the
	// directory belonging to whoever is typing. So plain `lan-sheriff status`
	// after an install reads a different database from the one the service is
	// writing, and answers confidently about the wrong instance: "no machines
	// are paired" while the service has two.
	fmt.Fprintf(out, "  lan-sheriff status --data-dir %s\n", quotePath(cfg.DataDir))
	fmt.Fprintln(out, "              what this machine shares, and with whom. The path matters:")
	fmt.Fprintln(out, "              without it you would be reading your own database, not the service's.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  lan-sheriff uninstall   remove it again")
	return nil
}

func runUninstall(cmd *cobra.Command, purge bool) error {
	out := cmd.OutOrStdout()

	if !serviceSupported() {
		return fmt.Errorf("nothing to uninstall on %s", runtime.GOOS)
	}
	if !hasAdmin() {
		return errors.New(elevateHint())
	}

	steps, err := uninstallService(purge)
	printSteps(out, steps)
	if err != nil {
		return err
	}
	if !purge {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "  The database is still in %s.\n", defaultServiceDataDir())
		fmt.Fprintln(out, "  Delete it with: lan-sheriff uninstall --purge")
	}
	return nil
}

func printSteps(w io.Writer, steps []step) {
	for _, s := range steps {
		fmt.Fprintf(w, "  %-11s %s\n", s.what, s.note)
	}
}

// dashboardURL turns a listen address into something clickable. A bare
// 0.0.0.0 is not somewhere a browser can go, so it is reported as this
// machine's name instead of pretending otherwise.
func dashboardURL(listen string) string {
	host, port, found := strings.Cut(listen, ":")
	if !found {
		return "http://" + listen
	}
	switch host {
	case "", "0.0.0.0", "[::]", "::":
		if h, err := os.Hostname(); err == nil && h != "" {
			return fmt.Sprintf("http://%s:%s", h, port)
		}
		return "http://localhost:" + port
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

// sameFile reports whether the source and destination are the same file, so
// that installing an already-installed binary does not truncate it by copying
// it onto itself.
func sameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

// installBinary copies src to dst.
//
// Writes to a temporary file beside the destination and renames it, so an
// interrupted copy cannot leave a half-written executable where a service is
// about to be pointed at one. The rename is atomic within a directory, which
// is why the temporary file goes there rather than in /tmp.
//
// It also removes the destination first, which matters on macOS: overwriting a
// running binary in place invalidates its cached code signature and the kernel
// kills it with SIGKILL. Unlinking gives the new copy a new inode and leaves
// any running process holding the old one, which then exits normally.
func installBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".lan-sheriff-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}

	_ = os.Remove(dst)
	return os.Rename(tmpName, dst)
}

// quotePath wraps a path in quotes when it needs them, and does not escape it.
//
// %q was the obvious thing and produced
// "C:\\ProgramData\\LAN Sheriff", because Go escapes backslashes inside a
// quoted string. That is correct Go and a broken command: nobody can paste it,
// and on Windows every path has backslashes, so the one platform where the
// hint matters most is the one where it was wrong. Printed as the user would
// type it, quoted only because "Program Files" has a space in it.
func quotePath(p string) string {
	if strings.ContainsAny(p, " \t") {
		return `"` + p + `"`
	}
	return p
}
