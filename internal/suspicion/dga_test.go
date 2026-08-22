package suspicion

import "testing"

// The names on the left are what generators produce; those on the right are what
// people register. The rule is worthless if it cannot separate them.
func TestLooksGenerated(t *testing.T) {
	generated := []string{
		"kqxvbnzmrtplwd.com",
		"xj4k9mzq7bvt.net",
		"vhzkpqrmxwbn.org",
		"zxcvbnmqwerty.info",
		"a7f3k9x2m8p1q4.biz",
	}
	for _, d := range generated {
		if got := looksGenerated(d); got < minDGAScore {
			t.Errorf("looksGenerated(%q) = %.2f, want at least %.2f", d, got, minDGAScore)
		}
	}

	ordinary := []string{
		"google.com", "cloudflare.com", "wikipedia.org", "raspberrypi.org",
		"stackoverflow.com", "wikipedia.org", "nationalgeographic.com",
		"my-holiday-photos.net", "the-corner-bakery.co.uk",
	}
	for _, d := range ordinary {
		if got := looksGenerated(d); got >= minDGAScore {
			t.Errorf("looksGenerated(%q) = %.2f, want below %.2f", d, got, minDGAScore)
		}
	}
}

// The reason the rule judges the registrable domain and not the full name.
// Content delivery puts randomness in subdomains constantly, and judging those
// would fire on ordinary browsing all day.
func TestRegistrableDomainIgnoresCDNRandomness(t *testing.T) {
	cases := []struct{ in, want string }{
		{"d3n8a8pro7vhmx.cloudfront.net", "cloudfront.net"},
		{"kqxvbnzmrtplwd.s3.amazonaws.com", "amazonaws.com"},
		{"abc123def456.execute-api.us-east-1.amazonaws.com", "amazonaws.com"},
		{"www.google.com", "google.com"},
		{"a.b.c.example.co.uk", "example.co.uk"},
		{"example.com", "example.com"},
		{"printer.local", ""},
		{"1.0.0.127.in-addr.arpa", ""},
		{"localhost", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := registrableDomain(c.in); got != c.want {
			t.Errorf("registrableDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A CDN hostname must survive the whole pipeline, not just the domain split.
func TestCDNHostnamesAreNotGenerated(t *testing.T) {
	for _, name := range []string{
		"d3n8a8pro7vhmx.cloudfront.net",
		"kqxvbnzmrtplwd.s3.amazonaws.com",
		"7f3k9x2m8p1q4.cdn.fastly.net",
		"xj4k9mzq7bvt.akamaiedge.net",
	} {
		reg := registrableDomain(name)
		if got := looksGenerated(reg); got >= minDGAScore {
			t.Errorf("%q reduced to %q scored %.2f, a CDN hostname would be reported", name, reg, got)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if h := shannon("aaaaaaaa"); h != 0 {
		t.Errorf("a single repeated character has entropy %.2f, want 0", h)
	}
	if h := shannon("abcdefgh"); h < 2.9 {
		t.Errorf("eight distinct characters gave %.2f, want 3", h)
	}
	if shannon("kqxvbnzmrtplwd") <= shannon("nationalgeographic") {
		t.Error("a generated-looking label should carry more entropy per character than a word")
	}
}

// Short names carry too little signal to judge either way.
func TestShortNamesAreNotJudged(t *testing.T) {
	for _, d := range []string{"bbc.co.uk", "x.com", "nyt.com", "abc.net"} {
		if got := looksGenerated(d); got != 0 {
			t.Errorf("looksGenerated(%q) = %.2f, want 0 for a short label", d, got)
		}
	}
}
