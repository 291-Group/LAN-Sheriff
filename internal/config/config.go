// Package config resolves where LAN Sheriff keeps its data and how it is
// configured. There is no configuration file: every setting has a working
// default, because a tool that needs configuring before it shows you anything
// has already failed its first principle.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
)

// AppName is used for directory names.
const AppName = "lan-sheriff"

// DefaultPort nods to the 291 house convention while staying above 1024 and
// out of its sibling's way.
//
// It is not 291: that is a privileged port, and LAN Sheriff's entire premise is
// that Deputy Mode needs no elevation, binding it would have meant sudo just
// to see a web page. It is not 2910 either, because LAN Orangutan listens
// there, and running both siblings on one machine is a normal thing to do.
const DefaultPort = 2911

// Config is the resolved runtime configuration.
type Config struct {
	Listen       string
	DataDir      string
	OpenBrowser  bool
	Locate       bool // look up this network's own position for the map origin
	CityDB       bool // fetch the larger city-precision GeoIP database
	Retention    store.Retention
	PollInterval time.Duration

	// AllowInsecure serves to the network without demanding a password.
	AllowInsecure bool
	// RequirePassword demands one even when bound to localhost.
	RequirePassword bool
	// TrustedHosts are additional Host header values accepted on a loopback
	// bind, so that a proxy terminating TLS in front of this server (tailscale
	// serve, nginx, Caddy) is not refused by the DNS-rebinding guard.
	TrustedHosts []string

	// Interface is the capture interface for Patrol Mode. Empty means choose
	// automatically.
	Interface string
	// Promiscuous asks the interface for traffic not addressed to this machine,
	// which is what makes other devices visible.
	Promiscuous bool

	// Sweep sends one small packet to each address on the local segment so the
	// operating system resolves its hardware address, which is what finds
	// devices that never speak to this machine.
	//
	// On by default because the Roster's promise is "everything on your
	// network", and passive observation alone quietly fails that. Disclosed in
	// the Help view and switchable, because a tool that promises not to be
	// sneaky must not put packets on the wire without saying so.
	Sweep bool

	// Notification targets. Every one is empty by default: these are the only
	// settings that cause anything to leave this machine, so none of them has a
	// default value that does something.
	// The Dispatch. Off unless Dispatch is set: enabling peering is an explicit
	// act, and there is no default-on path.
	Dispatch            bool
	DispatchListen      string
	DispatchAllowPublic bool

	NotifyWebhook  string
	NotifyNtfy     string
	NotifyDiscord  string
	NotifySlack    string
	NotifyMinScore float64

	// Offline serves an existing database without observing anything.
	//
	// For reading a record this machine did not produce, one copied off a Pi
	// on a mirror port, or off a machine being investigated. Without it the
	// ordinary build starts discovering and capturing immediately, and the
	// evidence acquires the reader's own network within seconds.
	Offline bool
}

// Default returns the zero-configuration configuration.
func Default() Config {
	return Config{
		Listen:      fmt.Sprintf("127.0.0.1:%d", DefaultPort),
		DataDir:     DefaultDataDir(),
		OpenBrowser: true,
		Locate:      true,
		CityDB:      true,
		Promiscuous: true,
		Sweep:       true,
		// Not a notification threshold so much as a definition of what is worth
		// interrupting somebody for.
		NotifyMinScore: 0.6,
		Retention:      store.DefaultRetention(),
		PollInterval:   2 * time.Second,
	}
}

// DefaultDataDir is the per-user location for the database and datasets.
func DefaultDataDir() string {
	if v := os.Getenv("LAN_SHERIFF_DATA_DIR"); v != "" {
		return v
	}
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", AppName)
		}
	case "windows":
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, AppName)
		}
	default:
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			return filepath.Join(v, AppName)
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".local", "share", AppName)
		}
	}
	return filepath.Join(os.TempDir(), AppName)
}

// PasswordFile is where the password hash created at first run is stored.
//
// It lives beside the data rather than in any config file, so that setting a
// password through the dashboard does not require the process to be able to
// rewrite its own configuration.
func (c Config) PasswordFile() string { return filepath.Join(c.DataDir, "password") }

// RequiresSetup reports whether the user must create a password before the
// dashboard becomes usable.
//
// Setup is demanded whenever the dashboard can be reached from somewhere other
// than this machine. Bound to loopback it is already private, so a password
// would be friction with no benefit, and an operator who has other protection
// in front of it can opt out entirely.
func (c Config) RequiresSetup(loopbackOnly bool) bool {
	if c.AllowInsecure {
		return false
	}
	if c.RequirePassword {
		return true
	}
	return !loopbackOnly
}

// DBPath is the database file inside the data directory.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "sheriff.db") }

// DatasetDir is where GeoIP and ASN databases live.
func (c Config) DatasetDir() string { return filepath.Join(c.DataDir, "datasets") }

// IsLocalOnly reports whether the listen address is loopback-only, which is
// what decides whether authentication is required.
func (c Config) IsLocalOnly() bool {
	host := c.Listen
	if i := lastColon(host); i >= 0 {
		host = host[:i]
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]", "":
		return true
	}
	return false
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}
