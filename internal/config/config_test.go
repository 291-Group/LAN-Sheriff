package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// RequiresSetup decides whether a dashboard holding a full record of someone's
// network is reachable without a password. Getting it wrong in the permissive
// direction is a security bug, so every combination is pinned.
func TestRequiresSetup(t *testing.T) {
	cases := []struct {
		name          string
		loopbackOnly  bool
		allowInsecure bool
		requirePass   bool
		want          bool
		why           string
	}{
		{
			name: "localhost only", loopbackOnly: true, want: false,
			why: "nothing else can reach it, so a password would be friction with no benefit",
		},
		{
			name: "exposed to the network", loopbackOnly: false, want: true,
			why: "anyone who can route to this host could otherwise read it",
		},
		{
			name: "exposed but explicitly opted out", loopbackOnly: false,
			allowInsecure: true, want: false,
			why: "the operator has taken responsibility, e.g. a tailnet or an authenticating proxy",
		},
		{
			name: "localhost but password demanded", loopbackOnly: true,
			requirePass: true, want: true,
			why: "shared machines are a real case",
		},
		{
			name: "both flags set, allow-insecure wins", loopbackOnly: false,
			allowInsecure: true, requirePass: true, want: false,
			why: "the explicit opt-out is the more specific instruction",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			cfg.AllowInsecure = c.allowInsecure
			cfg.RequirePassword = c.requirePass
			if got := cfg.RequiresSetup(c.loopbackOnly); got != c.want {
				t.Errorf("RequiresSetup() = %v, want %v, %s", got, c.want, c.why)
			}
		})
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	c := Default()

	if !strings.HasPrefix(c.Listen, "127.0.0.1:") {
		t.Errorf("the default bind must be loopback, got %q", c.Listen)
	}
	if !c.IsLocalOnly() {
		t.Error("the default configuration must be local only")
	}
	if c.AllowInsecure {
		t.Error("insecure exposure must never be the default")
	}
	// 291 is privileged and would demand sudo; 2910 belongs to LAN Orangutan.
	if DefaultPort != 2911 {
		t.Errorf("DefaultPort = %d, want 2911", DefaultPort)
	}
	if DefaultPort < 1024 {
		t.Error("the default port must not be privileged: Deputy Mode needs no elevation")
	}
	if c.Retention.MaxBytes <= 0 || c.Retention.Raw <= 0 {
		t.Error("retention must be bounded by default; an unbounded default is not Pi-safe")
	}
}

func TestIsLocalOnly(t *testing.T) {
	cases := []struct {
		listen string
		want   bool
	}{
		{"127.0.0.1:2911", true},
		{"localhost:2911", true},
		{"[::1]:2911", true},
		{"0.0.0.0:2911", false},
		{"192.168.1.50:2911", false},
		{":2911", true}, // no host given; treated as the loopback default
	}
	for _, c := range cases {
		cfg := Default()
		cfg.Listen = c.listen
		if got := cfg.IsLocalOnly(); got != c.want {
			t.Errorf("IsLocalOnly(%q) = %v, want %v", c.listen, got, c.want)
		}
	}
}

func TestPathsLiveUnderTheDataDir(t *testing.T) {
	c := Default()
	c.DataDir = filepath.Join("tmp", "sheriff-test")

	for name, got := range map[string]string{
		"DBPath":       c.DBPath(),
		"DatasetDir":   c.DatasetDir(),
		"PasswordFile": c.PasswordFile(),
	} {
		if !strings.HasPrefix(got, c.DataDir) {
			t.Errorf("%s() = %q, which is outside the data directory %q", name, got, c.DataDir)
		}
	}

	// The password belongs beside the data, not in a config file, so that
	// setting it through the UI needs no write access to configuration.
	if filepath.Base(c.PasswordFile()) != "password" {
		t.Errorf("unexpected password file name: %q", c.PasswordFile())
	}
}

func TestDataDirIsAbsoluteAndNamed(t *testing.T) {
	dir := DefaultDataDir()
	if dir == "" {
		t.Fatal("a data directory must always resolve")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("the data directory should be absolute, got %q", dir)
	}
	if !strings.Contains(dir, AppName) {
		t.Errorf("the data directory should be namespaced to %q, got %q", AppName, dir)
	}
}

func TestDataDirRespectsTheEnvironmentOverride(t *testing.T) {
	t.Setenv("LAN_SHERIFF_DATA_DIR", "/tmp/explicit-sheriff-dir")
	if got := DefaultDataDir(); got != "/tmp/explicit-sheriff-dir" {
		t.Errorf("DefaultDataDir() = %q, want the override", got)
	}
}
