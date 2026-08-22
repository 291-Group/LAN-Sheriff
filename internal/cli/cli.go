// Package cli is the command-line surface. Running the binary with no
// arguments starts the dashboard: that is the whole first-run experience.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/291-Group/LAN-Sheriff/internal/buildinfo"
)

// Build information, injected at link time by the Makefile and the release
// workflow.
var (
	Version   = "v.1.9.9PRB"
	Commit    = "none"
	BuildDate = "unknown"

	// Build is the number of commits reachable from this build, which makes it
	// a counter that goes up on its own as work happens and never needs to be
	// remembered or edited by hand. A beta tester saying "build 412" identifies
	// the exact tree; "v.1.9.9PRB" identifies six weeks of them.
	Build = "0"
)

// versionLine is the single description of this build, used by both the
// `version` subcommand and the --version flag. Written once because two
// literals is how they end up disagreeing.
func versionLine() string {
	return fmt.Sprintf("%s build %s (commit %s, built %s)", Version, Build, Commit, BuildDate)
}

// Execute runs the command-line interface.
func Execute() {
	// Published before any command runs, so anything deciding what advice to
	// give a user can tell a release binary from a `go build` one.
	buildinfo.Set(Commit)

	root := &cobra.Command{
		Use:   "lan-sheriff",
		Short: "Nothing leaves town unnoticed",
		Long: `LAN Sheriff shows you everything your machine and your network are
sending out to the internet: where it goes, who owns it, and which app is
responsible. It observes only, and never blocks or modifies traffic.

Run it with no arguments to start the dashboard.`,
		SilenceUsage: true,
		// And errors, because Execute below already prints them. With only
		// SilenceUsage set, cobra printed "Error: x" and then we printed
		// "error: x" underneath it, on every failure the CLI has ever had.
		SilenceErrors: true,
		// Setting this gives the root command a --version flag. Both it and the
		// `version` subcommand exist because both get typed: `version` is the
		// documented one, and --version is what decades of other command-line
		// tools have taught people to reach for. Somebody checking which build
		// they are on, which is the first thing a bug report needs, should not
		// have to discover our preference first.
		Version: versionLine(),
		// No subcommand means serve. Anything that needs setup before the user
		// sees value has already failed the point of the tool.
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd)
		},
	}

	root.SetVersionTemplate("lan-sheriff {{.Version}}\n")

	serve := &cobra.Command{
		Use:   "serve",
		Short: "Start capturing and serve the dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd)
		},
	}

	for _, c := range []*cobra.Command{root, serve} {
		addServeFlags(c)
	}

	root.AddCommand(serve, versionCmd(), statusCmd(), installCmd(), uninstallCmd())

	// Started by a service manager rather than a person? Then the whole
	// command runs under it, and there is no terminal to return an error to.
	// False everywhere except a Windows service, where it is the difference
	// between a clean shutdown and the database being torn away at every
	// reboot.
	if runAsService(root) {
		return
	}

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("lan-sheriff %s\n", versionLine())
		},
	}
}
