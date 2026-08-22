//go:build darwin

package cli

import (
	"os"
	"strings"
	"testing"
)

// The plist this writes into /Library/LaunchDaemons is built by string
// concatenation, and launchd is unforgiving: a malformed one is rejected with a
// message that sends people looking at permissions rather than at XML.
//
// Set GEN_PLIST to a path to write it out, then check it with the parser that
// actually decides, which is `plutil -lint`.
func TestLaunchdPlist(t *testing.T) {
	cfg := installConfig{
		Listen:  "127.0.0.1:2911",
		DataDir: "/usr/local/var/lan-sheriff",
		BinPath: "/usr/local/bin/lan-sheriff",
	}
	p := launchdPlist(cfg)

	for _, want := range []string{
		"<key>Label</key>",
		"com.291group.lan-sheriff",
		"<string>" + cfg.BinPath + "</string>",
		"<string>" + cfg.Listen + "</string>",
		"<string>" + cfg.DataDir + "</string>",
		"<key>RunAtLoad</key>",
		// Both streams to one file: the first question about a daemon that
		// will not start is what it said on the way down.
		"<key>StandardErrorPath</key>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist is missing %q", want)
		}
	}

	// KeepAlive on SuccessfulExit=false restarts it when it crashes and leaves
	// it alone when it is stopped deliberately. The other way round fights
	// `launchctl bootout`.
	if !strings.Contains(p, "<key>SuccessfulExit</key>") {
		t.Error("plist should keep the service alive only on unsuccessful exit")
	}

	if path := os.Getenv("GEN_PLIST"); path != "" {
		if err := os.WriteFile(path, []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
