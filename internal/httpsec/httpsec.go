// Package httpsec holds the HTTP hardening that sits in front of everything
// else: response headers, and the Host check that defends a loopback bind
// against DNS rebinding.
package httpsec

import (
	"net"
	"net/http"
	"strings"
)

// contentSecurityPolicy locks the dashboard to resources that ship inside the
// binary. LAN Sheriff loads no CDN scripts, no web fonts and no remote images,
// so the policy can be strict enough to make an injected script inert.
//
// connect-src includes ws: and wss: for the live stream, and 'self' covers the
// JSON API.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " + // the bundler inlines a small stylesheet
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self' ws: wss:; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'"

// Headers applies the standard security response headers.
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// The dashboard is a record of your network. Nothing about it should
		// leak into a Referer header on the way out.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// This tool has no business using any of these.
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}

// GuardHost rejects requests whose Host header does not name the local machine,
// when the server is bound to loopback.
//
// Without this, a page on the internet can point a hostname it controls at
// 127.0.0.1 and have the visitor's own browser read the dashboard, the browser
// is inside the trust boundary even though the attacker is not. Checking Host
// costs nothing and closes it.
// trusted names additional Host values to accept, for the case where something
// in front of this server is terminating TLS and forwarding to loopback. A
// proxy passes the browser's original Host through, so `tailscale serve` and an
// ordinary nginx or Caddy front end all arrive at a loopback bind carrying a
// name this guard would otherwise refuse. Without a way to name them, the
// deployment SECURITY.md recommends returns 403 to every request.
//
// They are named explicitly, one at a time, and there is no wildcard. The guard
// exists because an attacker chooses the Host header, so anything matching a
// pattern would hand back the thing being defended. A user who lists
// sheriff.example.com has said that name is theirs; that is a different
// statement from trusting whatever arrives.
func GuardHost(loopbackBind bool, trusted []string, next http.Handler) http.Handler {
	if !loopbackBind {
		return next
	}
	allowed := make(map[string]struct{}, len(trusted))
	for _, h := range trusted {
		if n := normaliseHost(h); n != "" {
			allowed[n] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if HostIsLoopback(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := allowed[normaliseHost(r.Host)]; ok {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "forbidden: unexpected Host header", http.StatusForbidden)
	})
}

// normaliseHost reduces a Host header or a configured name to a comparable
// form: no port, no brackets, lower case.
//
// The port is dropped from both sides rather than compared, because whether it
// appears is not the user's choice. A browser omits it for the default port and
// includes it otherwise, so requiring the configured value to match on that
// detail would make the flag work or fail depending on which port the proxy
// happens to listen on.
func normaliseHost(host string) string {
	h := strings.TrimSpace(host)
	if v, _, err := net.SplitHostPort(h); err == nil {
		h = v
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// HostIsLoopback reports whether an HTTP Host header names the local machine.
// The Host may carry a port, and an IPv6 literal may be bracketed; both are
// stripped before the address is examined.
func HostIsLoopback(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.TrimPrefix(strings.TrimSuffix(hostname, "]"), "[")

	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackBind reports whether a listen address only accepts connections from
// this machine. An empty host means every interface, which is not loopback.
func IsLoopbackBind(listen string) bool {
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	host = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
