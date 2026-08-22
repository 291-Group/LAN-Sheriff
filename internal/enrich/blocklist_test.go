package enrich

import (
	"strings"
	"testing"
)

func TestParseDomainListHandlesBothFormats(t *testing.T) {
	// Real lists come in both shapes, sometimes with comments and junk mixed in.
	input := `# Title: a list
! another comment style
0.0.0.0 doubleclick.net
0.0.0.0 ads.example.com # inline comment
127.0.0.1 tracker.example.org
plain-domain.example.net
::1 localhost
0.0.0.0 localhost
0.0.0.0 broadcasthost
0.0.0.0 not-a-domain
0.0.0.0 has_underscore.example.com

0.0.0.0 doubleclick.net
0.0.0.0 UPPER.Example.COM
0.0.0.0 trailing.example.com.
`
	got := parseDomainList(strings.NewReader(input))

	want := map[string]bool{
		"doubleclick.net":            true,
		"ads.example.com":            true,
		"tracker.example.org":        true,
		"plain-domain.example.net":   true,
		"has_underscore.example.com": true,
		"upper.example.com":          true,
		"trailing.example.com":       true,
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected domain parsed: %q", d)
		}
		delete(want, d)
	}
	for missing := range want {
		t.Errorf("missing domain: %q", missing)
	}

	// Duplicates collapse.
	seen := map[string]int{}
	for _, d := range got {
		seen[d]++
	}
	if seen["doubleclick.net"] != 1 {
		t.Errorf("doubleclick.net appeared %d times, want 1", seen["doubleclick.net"])
	}
}

func TestPlausibleDomain(t *testing.T) {
	for _, ok := range []string{"example.com", "a.b.c.example.co.uk", "x-y.example.net"} {
		if !plausibleDomain(ok) {
			t.Errorf("plausibleDomain(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "a.b", "localhost", "broadcasthost", "nodots",
		"has space.com", "has/slash.com", "UPPER.COM", // uppercase is normalized before this check
		strings.Repeat("a", 300) + ".com",
	} {
		if plausibleDomain(bad) {
			t.Errorf("plausibleDomain(%q) = true, want false", bad)
		}
	}
}

func TestCategoryMatchesParentDomains(t *testing.T) {
	// A list naming the parent must also label its subdomains, or the labels
	// would miss almost every real lookup.
	l := NewLabeller(t.TempDir())
	l.labels = map[string]string{
		"doubleclick.net": CategoryAds,
		"evil.example":    CategoryMalware,
	}
	l.loaded = true

	cases := map[string]string{
		"doubleclick.net":         CategoryAds,
		"stats.g.doubleclick.net": CategoryAds,
		"DOUBLECLICK.NET":         CategoryAds,
		"doubleclick.net.":        CategoryAds,
		"deep.sub.evil.example":   CategoryMalware,
		"notdoubleclick.net":      "",
		"example.com":             "",
		"":                        "",
	}
	for domain, want := range cases {
		got, ok := l.Category(domain)
		if want == "" {
			if ok {
				t.Errorf("Category(%q) = %q, want no match", domain, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("Category(%q) = %q/%v, want %q", domain, got, ok, want)
		}
	}
}

func TestCategoryDoesNotMatchASuffixThatIsNotADomainBoundary(t *testing.T) {
	// "notdoubleclick.net" must not match "doubleclick.net": a plain suffix
	// check would label unrelated domains.
	l := NewLabeller(t.TempDir())
	l.labels = map[string]string{"doubleclick.net": CategoryAds}
	l.loaded = true

	if _, ok := l.Category("notdoubleclick.net"); ok {
		t.Error("a suffix match across a label boundary must not count")
	}
	if _, ok := l.Category("mydoubleclick.net"); ok {
		t.Error("a suffix match across a label boundary must not count")
	}
}

func TestIsRedirectAddress(t *testing.T) {
	for _, yes := range []string{"0.0.0.0", "127.0.0.1", "::", "::1"} {
		if !isRedirectAddress(yes) {
			t.Errorf("isRedirectAddress(%q) = false", yes)
		}
	}
	for _, no := range []string{"192.168.1.1", "example.com", ""} {
		if isRedirectAddress(no) {
			t.Errorf("isRedirectAddress(%q) = true", no)
		}
	}
}

func TestUnloadedLabellerLabelsNothing(t *testing.T) {
	l := NewLabeller(t.TempDir())
	if l.Ready() {
		t.Error("a fresh labeller has loaded nothing")
	}
	if _, ok := l.Category("doubleclick.net"); ok {
		t.Error("an unloaded labeller must not claim to know anything")
	}
}
