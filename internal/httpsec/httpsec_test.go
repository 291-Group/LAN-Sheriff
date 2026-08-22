package httpsec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestHostIsLoopback(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"localhost:2911", true},
		{"LOCALHOST:2911", true},
		{"127.0.0.1", true},
		{"127.0.0.1:2911", true},
		{"127.0.0.5:2911", true}, // all of 127.0.0.0/8 is loopback
		{"[::1]:2911", true},
		{"::1", true},
		{"192.168.1.50:2911", false},
		{"sheriff.example.com", false},
		{"sheriff.example.com:2911", false},
		// The shape an attacker would use: a hostname they control that
		// resolves to the loopback address.
		{"rebind.evil.test:2911", false},
		{"", false},
	}
	for _, c := range cases {
		if got := HostIsLoopback(c.host); got != c.want {
			t.Errorf("HostIsLoopback(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		listen string
		want   bool
	}{
		{"127.0.0.1:2911", true},
		{"localhost:2911", true},
		{"[::1]:2911", true},
		{"0.0.0.0:2911", false},
		{"192.168.1.50:2911", false},
		{":2911", false}, // every interface
		{"", false},
	}
	for _, c := range cases {
		if got := IsLoopbackBind(c.listen); got != c.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", c.listen, got, c.want)
		}
	}
}

func TestGuardHostRejectsRebinding(t *testing.T) {
	h := GuardHost(true, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "attacker-controlled.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a foreign Host should be refused, got %d", rec.Code)
	}
}

func TestGuardHostAllowsLoopback(t *testing.T) {
	h := GuardHost(true, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "localhost:2911"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("a loopback Host should pass, got %d", rec.Code)
	}
}

func TestGuardHostInactiveWhenExposed(t *testing.T) {
	// Deliberately bound to the network, the Host header is expected to be a
	// LAN address or a hostname, so the guard must not apply.
	h := GuardHost(false, nil, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "sheriff.lan:2911"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("the guard should be inactive on a network bind, got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	Headers(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("a content security policy should always be set")
	} else {
		// The two directives that matter most for a page holding this data.
		for _, must := range []string{"frame-ancestors 'none'", "default-src 'self'"} {
			if !strings.Contains(csp, must) {
				t.Errorf("CSP is missing %q: %s", must, csp)
			}
		}
	}
}

// A proxy in front of a loopback bind forwards the browser's original Host, so
// without a way to name it, the deployment SECURITY.md recommends (tailscale
// serve, or nginx and Caddy terminating TLS) got 403 on every request.
func TestGuardHostAcceptsATrustedProxyName(t *testing.T) {
	h := GuardHost(true, []string{"sheriff.example.com", "MACHINE.tail1234.ts.net"}, okHandler())

	pass := []string{
		"sheriff.example.com",      // exactly as configured
		"sheriff.example.com:8443", // proxy on a non-default port
		"SHERIFF.EXAMPLE.COM",      // Host headers are not case sensitive
		"machine.tail1234.ts.net",  // configured in mixed case
		"sheriff.example.com.",     // a fully qualified name with the root dot
		"127.0.0.1:2911",           // loopback still works alongside
	}
	for _, host := range pass {
		req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q should be accepted, got %d", host, rec.Code)
		}
	}

	// Naming one host must not open the guard generally, and in particular must
	// not admit anything merely resembling it. An attacker picks the Host
	// header, so a suffix or substring match would hand back what is guarded.
	refuse := []string{
		"attacker-controlled.example.com",
		"sheriff.example.com.attacker.com", // the trusted name as a prefix
		"evil-sheriff.example.com",         // as a suffix
		"example.com",                      // the parent domain
		"sub.sheriff.example.com",          // a child of it
		"",
	}
	for _, host := range refuse {
		req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Host %q must be refused, got %d", host, rec.Code)
		}
	}
}

// The guard with no trusted hosts configured must behave exactly as before.
func TestGuardHostWithoutTrustedHostsIsUnchanged(t *testing.T) {
	h := GuardHost(true, nil, okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "sheriff.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("with nothing trusted, a foreign Host must be refused, got %d", rec.Code)
	}
}
