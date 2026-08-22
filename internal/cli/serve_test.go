package cli

import (
	"testing"

	"github.com/291-Group/LAN-Sheriff/internal/config"
)

// --offline must reach nothing, and registration lookups are the case that got
// missed.
//
// The flag's own help text promises "no capture, discovery, enrichment or
// location lookups". Capture, discovery and the dataset fetches were all gated
// on it. The RDAP resolver was constructed unconditionally in the middle of a
// struct literal, so an offline instance answered a Rap Sheet by sending the
// address to IANA and then to a regional registry, and returned live data with
// a fetched_at of that second. Confirmed against a running binary before this
// test was written.
//
// The distinction the flag exists for: the other datasets are files on a
// schedule, and downloading one tells the provider that somebody downloaded a
// file. RDAP sends an address seen on this network, so it tells a third party
// which endpoints the user is looking at, one click at a time. Somebody who
// passes --offline is refusing exactly that.
func TestOfflineDoesNotResolveRegistrations(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()

	cfg.Offline = true
	if r := rdapUnlessOffline(cfg); r != nil {
		t.Error("--offline must not construct an RDAP resolver: an offline instance would " +
			"send observed addresses to IANA and a regional registry")
	}

	// And the ordinary case still has one, or the Rap Sheet silently loses its
	// registration section for everybody.
	cfg.Offline = false
	if r := rdapUnlessOffline(cfg); r == nil {
		t.Error("a normal instance must resolve registrations")
	}
}
