package web

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// The page nobody looks at is the page that rots, and this one is invisible by
// construction: it appears only in a browser with scripting disabled, which is
// not the browser it will ever be developed in. So the tests do the looking.

// TestInjectedIntoTheRealDocument is the one that matters. Everything else here
// tests functions in isolation; this asserts against the index.html that is
// actually embedded in the binary, which is the thing the bundler rewrites.
//
// Vite is free to reformat the entry document, and if it ever emits something
// the patterns do not match, injection returns false, every language is dropped
// from the map, and the dashboard carries on working perfectly with no fallback
// page at all. That failure is completely silent from the outside, which is why
// it is asserted rather than assumed.
func TestInjectedIntoTheRealDocument(t *testing.T) {
	sub, err := FS()
	if err != nil {
		t.Fatalf("no embedded dashboard: %v", err)
	}
	docs := indexDocs(sub)
	if len(docs) != len(noscriptTexts) {
		t.Fatalf("injected into %d of %d languages; the entry document is not the shape "+
			"internal/web expects, so the no-JS page would silently not ship",
			len(docs), len(noscriptTexts))
	}
	en := string(docs["en"])
	for _, want := range []string{"<noscript>", "</noscript>", `lang="en"`, `dir="ltr"`, cmdStatus} {
		if !strings.Contains(en, want) {
			t.Errorf("the served document is missing %q", want)
		}
	}
	// The block belongs inside the body. Placed in the head it still parses,
	// but the styles land before the reset and the layout is wrong.
	if strings.Index(en, "<noscript>") < strings.Index(en, "<body") {
		t.Error("the noscript block was placed before <body>")
	}
}

func TestServesTheReadersLanguage(t *testing.T) {
	h := Handler()
	for _, c := range []struct {
		header, lang, dir, phrase string
	}{
		{"", "en", "ltr", noscriptTexts["en"].Title},
		{"fr-CA,fr;q=0.9", "fr", "ltr", noscriptTexts["fr"].Title},
		{"pt-BR", "pt", "ltr", noscriptTexts["pt"].Title},
		{"ar", "ar", "rtl", noscriptTexts["ar"].Title},
		{"he-IL", "he", "rtl", noscriptTexts["he"].Title},
		{"zh-Hans-CN,zh;q=0.9", "zh", "ltr", noscriptTexts["zh"].Title},
		// Nothing recognised anywhere in the header.
		{"is,fo;q=0.8", "en", "ltr", noscriptTexts["en"].Title},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			req.Header.Set("Accept-Language", c.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%q: status %d", c.header, rec.Code)
			continue
		}
		body := rec.Body.String()
		if !strings.Contains(body, `lang="`+c.lang+`"`) {
			t.Errorf("%q: expected lang=%q", c.header, c.lang)
		}
		if !strings.Contains(body, `dir="`+c.dir+`"`) {
			t.Errorf("%q: expected dir=%q", c.header, c.dir)
		}
		if !strings.Contains(body, c.phrase[:20]) {
			t.Errorf("%q: the %s heading is not in the page", c.header, c.lang)
		}
		if v := rec.Header().Get("Vary"); !strings.Contains(v, "Accept-Language") {
			t.Errorf("%q: Vary is %q, so a shared cache may serve the wrong language", c.header, v)
		}
	}
}

// A client-side route reloaded from the address bar goes through the not-found
// branch, and that branch has to produce the fallback page too. It did not, in
// the first draft: only "/" did, so /#roster reloaded without JS showed a blank
// screen, which is the majority of how anyone arrives at a view.
func TestFallbackRoutesAlsoGetThePage(t *testing.T) {
	h := Handler()
	for _, path := range []string{"/", "/index.html", "/roster", "/precinct/deep/link"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Language", "de")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), "<noscript>") {
			t.Errorf("%s served no fallback page", path)
		}
		if !strings.Contains(rec.Body.String(), `lang="de"`) {
			t.Errorf("%s did not honour Accept-Language", path)
		}
	}
}

// Assets must not be rewritten. Injecting into a JavaScript bundle because it
// happened to contain the string "<body" would corrupt it.
func TestAssetsAreUntouched(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/badge.svg", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("badge.svg: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<noscript>") {
		t.Error("an asset was rewritten")
	}
}

func TestPickLang(t *testing.T) {
	for header, want := range map[string]string{
		"":                          "en",
		"en":                        "en",
		"EN-GB":                     "en",
		"fr-CH, fr;q=0.9, en;q=0.8": "fr",
		"en;q=0.5, ja;q=0.9":        "ja", // q order beats header order
		"de;q=0, fr":                "fr", // q=0 means "not this one"
		"xx-YY,ru":                  "ru",
		"  es  ,  en  ":             "es",
		"garbage;;;q=x,hi":          "hi", // malformed, must not panic or win
		"zh-Hant":                   "zh",
		"bn-BD;q=1.0":               "bn",
	} {
		if got := pickLang(header); got != want {
			t.Errorf("pickLang(%q) = %q, want %q", header, got, want)
		}
	}
}

// Every field of every catalogue must be filled. A zero-valued string compiles
// happily and renders as an empty paragraph, which on this page would read as
// the software having nothing to say for itself.
func TestNoCatalogueHasAHole(t *testing.T) {
	for lang, txt := range noscriptTexts {
		v := reflect.ValueOf(txt)
		for i := 0; i < v.NumField(); i++ {
			if strings.TrimSpace(v.Field(i).String()) == "" {
				t.Errorf("%s: %s is empty", lang, v.Type().Field(i).Name)
			}
		}
	}
}

// House style, enforced rather than remembered: no em dashes in anything that
// ships, and the untranslated product name spelled the one way.
func TestHouseStyle(t *testing.T) {
	for lang, txt := range noscriptTexts {
		v := reflect.ValueOf(txt)
		for i := 0; i < v.NumField(); i++ {
			s := v.Field(i).String()
			name := v.Type().Field(i).Name
			if strings.ContainsAny(s, "—–") {
				t.Errorf("%s: %s contains a dash that is not allowed to ship", lang, name)
			}
			if strings.Contains(s, "LAN sheriff") || strings.Contains(s, "Lan Sheriff") {
				t.Errorf("%s: %s misspells the product name", lang, name)
			}
		}
	}
}

// The commands are the promise this page makes: that refusing JavaScript does
// not cost you your own data. They are checked for shape here; that they run is
// covered by the API tests for the endpoints they call.
func TestCommandsAreReachableEndpoints(t *testing.T) {
	for _, c := range []string{cmdCSV, cmdJSON, cmdLogin} {
		if !strings.Contains(c, ":2911") {
			t.Errorf("%q does not use the documented port", c)
		}
	}
	for _, want := range []string{"/api/export", "/api/auth/login", "/api/summary"} {
		found := false
		for _, c := range []string{cmdCSV, cmdJSON, cmdLogin} {
			if strings.Contains(c, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no command exercises %s", want)
		}
	}
	if !strings.HasPrefix(cmdStatus, "lan-sheriff ") {
		t.Errorf("%q is not a lan-sheriff subcommand", cmdStatus)
	}
}

// Prose goes through html.EscapeString, so a quotation mark in a translation
// cannot close an attribute or a tag. Checked with a planted catalogue rather
// than trusted, because the escaping is one call and one call is easy to lose.
func TestProseCannotBreakOutOfTheMarkup(t *testing.T) {
	saved := noscriptTexts["en"]
	defer func() { noscriptTexts["en"] = saved }()

	hostile := saved
	hostile.Title = `</noscript><script>alert(1)</script>`
	noscriptTexts["en"] = hostile

	out := renderNoscript("en")
	if strings.Contains(out, "<script>") {
		t.Error("a translation was able to inject a tag")
	}
	if strings.Count(out, "</noscript>") != 1 {
		t.Error("a translation was able to close the noscript block early")
	}
}
