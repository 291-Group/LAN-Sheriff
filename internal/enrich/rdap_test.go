package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A realistic slice of IANA's bootstrap file, including the bare "8" form the
// v4 registry uses for a /8 and an overlapping pair to exercise longest-match.
const bootstrapV4 = `{
  "description": "RDAP bootstrap file for IPv4 address allocations",
  "services": [
    [["8"], ["https://rdap.arin.net/registry/"]],
    [["93.184.0.0/15"], ["https://rdap.db.ripe.net/"]],
    [["93.0.0.0/8"], ["http://insecure.example/", "https://rdap.example-rir.net/"]]
  ]
}`

func newTestRDAP(t *testing.T) *RDAP {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, bootstrapFileV4), []byte(bootstrapV4), 0o600); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	return NewRDAP(dir)
}

func TestBootstrapPrefixParsing(t *testing.T) {
	r := newTestRDAP(t)
	idx, err := r.loadBootstrap(context.Background(), false)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}

	// The bare "8" must be read as 8.0.0.0/8, not rejected.
	var sawSlashEight bool
	for _, e := range idx.entries {
		if e.prefix.String() == "8.0.0.0/8" {
			sawSlashEight = true
		}
	}
	if !sawSlashEight {
		t.Error(`the bare "8" form should expand to 8.0.0.0/8`)
	}
}

func TestServiceForPrefersTheMostSpecificPrefix(t *testing.T) {
	r := newTestRDAP(t)
	ctx := context.Background()

	// 93.184.216.34 falls inside both 93.0.0.0/8 and 93.184.0.0/15. The more
	// specific one governs, exactly as routing would resolve it.
	got, ok := r.serviceFor(ctx, netip.MustParseAddr("93.184.216.34"))
	if !ok {
		t.Fatal("expected a service for an address inside the registry")
	}
	if !strings.Contains(got, "ripe") {
		t.Errorf("service = %q, want the /15 (RIPE) entry rather than the /8", got)
	}

	// An address only in the /8 gets the /8's service.
	got, ok = r.serviceFor(ctx, netip.MustParseAddr("93.1.2.3"))
	if !ok || !strings.Contains(got, "example-rir") {
		t.Errorf("service = %q (ok=%v), want the /8 entry", got, ok)
	}
}

func TestServiceForSkipsPlainHTTP(t *testing.T) {
	// An RDAP query over plain HTTP would leak which address a user is
	// investigating, which is precisely what this product exists to prevent.
	r := newTestRDAP(t)
	got, _ := r.serviceFor(context.Background(), netip.MustParseAddr("93.1.2.3"))
	if strings.HasPrefix(got, "http://") {
		t.Errorf("chose an insecure service: %q", got)
	}
}

func TestServiceForUnknownAddress(t *testing.T) {
	r := newTestRDAP(t)
	if _, ok := r.serviceFor(context.Background(), netip.MustParseAddr("203.0.113.1")); ok {
		t.Error("an address outside the registry should have no service")
	}
}

func TestLookupParsesAnRDAPResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/ip/93.184.216.34") {
			t.Errorf("unexpected query path %q", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/rdap+json" {
			t.Errorf("Accept = %q, want application/rdap+json", got)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(`{
		  "handle": "93.184.216.0 - 93.184.216.255",
		  "name": "EDGECAST-NETBLK-03",
		  "country": "US",
		  "startAddress": "93.184.216.0",
		  "endAddress": "93.184.216.255",
		  "events": [
		    {"eventAction": "registration", "eventDate": "2012-06-22T00:00:00Z"},
		    {"eventAction": "last changed", "eventDate": "2021-03-04T12:00:00Z"}
		  ],
		  "entities": [
		    {"roles": ["registrant"],
		     "vcardArray": ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Edgecast Inc."]]]},
		    {"roles": ["abuse"],
		     "vcardArray": ["vcard", [["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.net"]]]}
		  ]
		}`))
	}))
	defer srv.Close()

	r := newTestRDAP(t)
	reg, ok := r.query(context.Background(), srv.URL, "93.184.216.34")
	if !ok {
		t.Fatal("expected the response to be accepted")
	}

	checks := map[string]string{
		"handle":       reg.Handle,
		"name":         reg.Name,
		"country":      reg.Country,
		"range":        reg.Range,
		"organization": reg.Organization,
		"abuse":        reg.Abuse,
		"registered":   reg.Registered,
		"updated":      reg.Updated,
	}
	want := map[string]string{
		"handle":       "93.184.216.0 - 93.184.216.255",
		"name":         "EDGECAST-NETBLK-03",
		"country":      "US",
		"range":        "93.184.216.0 to 93.184.216.255",
		"organization": "Edgecast Inc.",
		"abuse":        "abuse@example.net",
		"registered":   "2012-06-22",
		"updated":      "2021-03-04",
	}
	for field, got := range checks {
		if got != want[field] {
			t.Errorf("%s = %q, want %q", field, got, want[field])
		}
	}
}

func TestQueryRejectsAnErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	r := newTestRDAP(t)
	if _, ok := r.query(context.Background(), srv.URL, "203.0.113.1"); ok {
		t.Error("a 404 should not be treated as a registration")
	}
}

func TestLookupCachesNegativeResults(t *testing.T) {
	// Without this, opening a Rap Sheet for an unregistered address would hit
	// the network on every single view.
	r := newTestRDAP(t)
	ip := "203.0.113.1" // outside the seeded registry

	if _, ok := r.Lookup(context.Background(), ip); ok {
		t.Fatal("expected no registration")
	}
	r.mu.RLock()
	_, cached := r.cache[ip]
	r.mu.RUnlock()
	if !cached {
		t.Error("a miss should be remembered so it is not retried every time")
	}
}

func TestLookupRejectsGarbage(t *testing.T) {
	r := newTestRDAP(t)
	if _, ok := r.Lookup(context.Background(), "not-an-address"); ok {
		t.Error("an unparseable address should not produce a registration")
	}
}

func TestVCardNameAndEmail(t *testing.T) {
	// jCard nests the properties two levels deep, which is the fiddly part.
	vcard := []any{"vcard", []any{
		[]any{"version", map[string]any{}, "text", "4.0"},
		[]any{"fn", map[string]any{}, "text", "Example Org"},
		[]any{"email", map[string]any{}, "text", "abuse@example.net"},
	}}
	name, email := vcardNameAndEmail(vcard)
	if name != "Example Org" {
		t.Errorf("name = %q", name)
	}
	if email != "abuse@example.net" {
		t.Errorf("email = %q", email)
	}

	// Malformed shapes must not panic.
	for _, bad := range []([]any){nil, {"vcard"}, {"vcard", "not-an-array"},
		{"vcard", []any{[]any{"fn"}}}} {
		if n, e := vcardNameAndEmail(bad); n != "" || e != "" {
			t.Errorf("malformed vcard yielded %q/%q", n, e)
		}
	}
}

func TestShortDate(t *testing.T) {
	cases := map[string]string{
		"2012-06-22T00:00:00Z":      "2012-06-22",
		"2021-03-04T12:30:00+02:00": "2021-03-04",
		"2019-01-01":                "2019-01-01",
		"garbage":                   "garbage",
	}
	for in, want := range cases {
		if got := shortDate(in); got != want {
			t.Errorf("shortDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFileAgeOfMissingFileIsEffectivelyInfinite(t *testing.T) {
	// The bootstrap refresh decision depends on this, so a missing file must
	// read as stale rather than fresh.
	if fileAge(filepath.Join(t.TempDir(), "nope.json")) < 365*24*time.Hour {
		t.Error("a missing file should be treated as very old")
	}
}
