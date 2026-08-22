// Package web serves the dashboard, baked into the binary.
//
// The built frontend under dist/ is committed rather than gitignored. That is a
// deliberate trade: it makes diffs noisier, but it means `go install` produces a
// working binary for someone who has never had Node installed, which matters
// more for a tool whose whole promise is "run one thing and it works".
// Rebuild it with `make web`.
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// Go's table has no entry for .webmanifest, so http.FileServer fell back to
// content sniffing and served the manifest as text/plain. Browsers mostly
// tolerate that and Chrome logs a warning about it, which is the sort of thing
// that sits in a console forever because it never quite breaks anything.
//
// Registered here rather than at a call site because it is a property of what
// this package serves, and init runs before any handler is built.
func init() {
	if err := mime.AddExtensionType(".webmanifest", "application/manifest+json"); err != nil {
		// Only returned for a malformed extension, which this is not. Nothing
		// useful to do at process start, and a wrong content type is not worth
		// refusing to serve the dashboard over.
		_ = err
	}
}

//go:embed all:dist
var dist embed.FS

// FS returns the built dashboard as a filesystem rooted at the asset directory.
func FS() (fs.FS, error) { return fs.Sub(dist, "dist") }

// Handler serves the dashboard, falling back to index.html for any path the
// build did not produce so client-side routes survive a page reload.
func Handler() http.Handler {
	sub, err := FS()
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "dashboard not built: run `make web`", http.StatusInternalServerError)
		})
	}
	files := http.FileServer(http.FS(sub))

	// The entry document is built once per language at startup rather than per
	// request. Twelve small documents, and it means a request cannot pay for the
	// regular expressions.
	docs := indexDocs(sub)

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		lang := pickLang(r.Header.Get("Accept-Language"))
		doc, ok := docs[lang]
		if !ok {
			doc, ok = docs["en"]
		}
		if !ok {
			// Injection failed for every language, so index.html was not the
			// shape this package expects. Serve it as it is: losing the
			// fallback page is bad, losing the dashboard is worse.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-store")
			files.ServeHTTP(w, r)
			return
		}
		// Vary, because the body now depends on the request header. Without it
		// any cache between here and the reader is entitled to hand a French
		// reader the German copy.
		w.Header().Set("Vary", "Accept-Language")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(doc)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(doc)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			// Unknown path: hand it to the SPA rather than 404ing.
			serveIndex(w, r)
			return
		}
		if p == "index.html" {
			serveIndex(w, r)
			return
		}
		// Vite fingerprints asset filenames, so they can be cached hard; the
		// entry document must not be.
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		files.ServeHTTP(w, r)
	})
}

// indexDocs renders index.html once per language, each with the no-JS fallback
// page injected and the document language and direction set.
//
// A language whose injection fails is left out of the map rather than stored
// unmodified, so that the caller can tell the difference between "translated"
// and "silently did nothing". Inserting text with a pattern that quietly stops
// matching is the way this codebase has lost rendered content before.
func indexDocs(sub fs.FS) map[string][]byte {
	raw, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil
	}
	docs := make(map[string][]byte, len(noscriptTexts))
	for lang := range noscriptTexts {
		if doc, ok := injectNoscript(raw, lang); ok {
			docs[lang] = doc
		}
	}
	return docs
}
