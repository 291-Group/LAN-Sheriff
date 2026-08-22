package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testFinding() Finding {
	return Finding{Rule: "beaconing", Subject: "Kitchen tablet", Score: 0.8, At: time.Now()}
}

// The single most important property: a notification must not carry network
// detail off the machine. It travels through somebody else's server and often
// lands on a lock screen.
func TestPayloadCarriesNothingSensitive(t *testing.T) {
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()

	w := Webhook{URL: srv.URL}
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = &http.Client{} }()

	if err := w.Send(context.Background(), testFinding()); err != nil {
		t.Fatal(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload is not JSON: %s", body)
	}
	// Exactly these keys, and no more. A new field here is a new disclosure.
	want := map[string]bool{"source": true, "rule": true, "subject": true, "score": true, "at": true, "message": true}
	for k := range payload {
		if !want[k] {
			t.Errorf("payload carries unexpected field %q, every field here leaves the machine", k)
		}
	}
	for k := range want {
		if _, ok := payload[k]; !ok {
			t.Errorf("payload is missing %q", k)
		}
	}
}

// A burst of findings must not become a burst of messages.
func TestRateLimitThrottlesABurst(t *testing.T) {
	var mu sync.Mutex
	sent := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sent++
		mu.Unlock()
	}))
	defer srv.Close()
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = &http.Client{} }()

	n := &Notifier{Targets: []Target{Webhook{URL: srv.URL}}}
	for i := 0; i < 20; i++ {
		n.Notify(context.Background(), testFinding())
	}
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if sent != 1 {
		t.Errorf("twenty findings produced %d messages, want 1 within the rate limit", sent)
	}
}

// A channel can be set to carry only what matters.
func TestMinScoreSuppresses(t *testing.T) {
	var mu sync.Mutex
	sent := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sent++
		mu.Unlock()
	}))
	defer srv.Close()
	http.DefaultClient = srv.Client()
	defer func() { http.DefaultClient = &http.Client{} }()

	n := &Notifier{Targets: []Target{Webhook{URL: srv.URL}}, MinScore: 0.9}
	n.Notify(context.Background(), testFinding()) // score 0.8
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if sent != 0 {
		t.Errorf("a finding below the threshold was sent")
	}
}

// Nothing configured means nothing happens.
func TestDisabledByDefault(t *testing.T) {
	var n *Notifier
	if n.Enabled() {
		t.Error("a nil notifier reports itself enabled")
	}
	empty := &Notifier{}
	if empty.Enabled() {
		t.Error("a notifier with no targets reports itself enabled")
	}
	// Must not panic.
	empty.Notify(context.Background(), testFinding())
}

// Sending findings unencrypted across the internet would be a poor look for this
// particular product.
func TestRefusesPlainHTTPToTheInternet(t *testing.T) {
	if _, err := NewWebhook("http://example.com/hook"); err == nil {
		t.Error("accepted plain HTTP to a public host")
	}
	// A local endpoint is the case where it is reasonable.
	if _, err := NewWebhook("http://192.168.1.10:8080/hook"); err != nil {
		t.Errorf("rejected plain HTTP to a private address: %v", err)
	}
	if _, err := NewWebhook("http://localhost:9000/hook"); err != nil {
		t.Errorf("rejected plain HTTP to localhost: %v", err)
	}
	if _, err := NewWebhook("https://example.com/hook"); err != nil {
		t.Errorf("rejected a valid HTTPS endpoint: %v", err)
	}
	for _, bad := range []string{"", "not a url", "ftp://example.com", "file:///etc/passwd"} {
		if _, err := NewWebhook(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A mistyped service URL should be reported when it is set, not silently fail
// for weeks.
func TestServiceURLsAreChecked(t *testing.T) {
	if _, err := NewDiscord("https://example.com/hook"); err == nil {
		t.Error("accepted a non-Discord URL as a Discord webhook")
	}
	if _, err := NewSlack("https://example.com/hook"); err == nil {
		t.Error("accepted a non-Slack URL as a Slack webhook")
	}
	if _, err := NewDiscord("https://discord.com/api/webhooks/1/abc"); err != nil {
		t.Errorf("rejected a valid Discord webhook: %v", err)
	}
	if _, err := NewSlack("https://hooks.slack.com/services/A/B/C"); err != nil {
		t.Errorf("rejected a valid Slack webhook: %v", err)
	}
}

func TestMessageIsOneReadableLine(t *testing.T) {
	m := Message(testFinding())
	if !strings.Contains(m, "Beaconing") || !strings.Contains(m, "Kitchen tablet") {
		t.Errorf("Message = %q", m)
	}
	if strings.Contains(m, "\n") {
		t.Error("a notification should be a single line")
	}
}
