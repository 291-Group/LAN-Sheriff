// Package notify sends findings to somewhere outside this machine.
//
// It is the only part of LAN Sheriff that does so, and the only part that can
// ever cause information about a network to reach a third party. Everything here
// is shaped by that:
//
//   - **Off unless configured.** No target has a default. An unset target is not
//     a disabled feature, it is an absent one.
//   - **The payload is deliberately thin.** A notification says which rule fired
//     and what it fired about, and nothing else. It does not carry the
//     organization, the address, the interval, or the counts, those live in the
//     dashboard, behind the user's own authentication. A push notification
//     travels through somebody else's server and often ends up on a lock screen.
//   - **It cannot delay observation.** Sending happens on its own goroutine with
//     a short timeout; a webhook that hangs must never slow down capture.
//   - **It fails quietly and does not retry.** A missed notification is a small
//     loss. A retry storm against somebody's server, from a tool that is
//     supposed to be unobtrusive, is a much larger one.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Finding is the thin shape a notification carries.
//
// Deliberately not the store's Finding: this is what leaves the machine, and it
// should be obvious from the type alone exactly how much that is.
type Finding struct {
	// Rule is the stable code, such as "beaconing".
	Rule string
	// Subject is the device's display name, or its address if it has no name.
	Subject string
	// Score is the finding's weight, so a recipient can filter.
	Score float64
	At    time.Time
}

// Target is somewhere notifications go.
type Target interface {
	Name() string
	Send(ctx context.Context, f Finding) error
}

// Notifier fans a finding out to every configured target.
type Notifier struct {
	Targets []Target
	// MinScore suppresses notifications below a threshold, so a channel can be
	// set to carry only what matters.
	MinScore float64

	// Rate limiting: a burst of findings must not become a burst of messages.
	mu       sync.Mutex
	lastSent time.Time
	sentHour int
	hourFrom time.Time
}

const (
	// sendTimeout bounds a single delivery. Short: this is a notification, not a
	// transaction, and a hanging endpoint must not accumulate goroutines.
	sendTimeout = 8 * time.Second

	// minGap is the shortest interval between two messages, so a burst of
	// findings arrives as a trickle rather than a flood.
	minGap = 20 * time.Second

	// maxPerHour is a hard ceiling. Somebody whose network is genuinely on fire
	// does not need two hundred notifications about it; they need to open the
	// dashboard.
	maxPerHour = 12
)

// Enabled reports whether anything is configured. Used to avoid doing work when
// nothing would come of it.
func (n *Notifier) Enabled() bool { return n != nil && len(n.Targets) > 0 }

// Notify sends a finding to every target, subject to the rate limit.
//
// Returns immediately: delivery happens in the background, because nothing about
// observing a network should wait on somebody else's server.
func (n *Notifier) Notify(ctx context.Context, f Finding) {
	if !n.Enabled() || f.Score < n.MinScore {
		return
	}
	if !n.allow() {
		return
	}
	for _, t := range n.Targets {
		go func(t Target) {
			sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
			defer cancel()
			if err := t.Send(sendCtx, f); err != nil && ctx.Err() == nil {
				// Logged once, not retried. See the package comment.
				slog.Warn("could not send notification", "target", t.Name(), "err", err)
			}
		}(t)
	}
}

// allow applies the rate limit.
func (n *Notifier) allow() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	if now.Sub(n.hourFrom) > time.Hour {
		n.hourFrom, n.sentHour = now, 0
	}
	if n.sentHour >= maxPerHour || now.Sub(n.lastSent) < minGap {
		return false
	}
	n.lastSent = now
	n.sentHour++
	return true
}

// Message is the human-readable line a target sends.
//
// One sentence, naming the rule and the subject. Any more would be putting
// network detail on somebody's lock screen.
func Message(f Finding) string {
	return fmt.Sprintf("LAN Sheriff: %s, %s", ruleTitle(f.Rule), f.Subject)
}

// ruleTitle renders a rule code readably without translating it: a notification
// leaves the machine, and the dashboard's language is not necessarily the
// recipient's.
func ruleTitle(code string) string {
	if code == "" {
		return "finding"
	}
	parts := strings.Split(code, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i == 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

// post is the shared delivery path: one request, no retry, body drained so the
// connection can be reused.
func post(ctx context.Context, endpoint, contentType string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "lan-sheriff")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", endpoint, resp.Status)
	}
	return nil
}

// validateEndpoint rejects a target that is not a plausible HTTPS endpoint.
//
// Checked at configuration time rather than at send time, so a mistyped URL is
// reported when it is set rather than silently failing for weeks. Plain HTTP is
// permitted only for a private address: sending findings unencrypted across the
// internet would be a poor look for this particular product.
func validateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isPrivateHost(u.Hostname()) {
			return nil, fmt.Errorf("refusing to send findings over plain HTTP to %s; use https", u.Hostname())
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", raw)
	}
	return u, nil
}

func jsonBody(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
