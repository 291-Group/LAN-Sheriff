package notify

import (
	"context"
	"net/netip"
	"strings"
)

// The delivery formats.
//
// Four shapes cover the services people actually use. Each sends the same thin
// message; the differences are entirely in what the receiving service expects.

// Webhook posts a small JSON object to any endpoint.
//
// The general case, and the one to prefer: it goes wherever the user chooses
// rather than through a third party's infrastructure.
type Webhook struct{ URL string }

func NewWebhook(raw string) (*Webhook, error) {
	if _, err := validateEndpoint(raw); err != nil {
		return nil, err
	}
	return &Webhook{URL: raw}, nil
}

func (Webhook) Name() string { return "webhook" }

func (w Webhook) Send(ctx context.Context, f Finding) error {
	return post(ctx, w.URL, "application/json", jsonBody(map[string]any{
		"source":  "lan-sheriff",
		"rule":    f.Rule,
		"subject": f.Subject,
		"score":   f.Score,
		"at":      f.At.UTC().Format("2006-01-02T15:04:05Z"),
		"message": Message(f),
	}))
}

// Ntfy posts a plain-text line to an ntfy topic.
type Ntfy struct{ URL string }

func NewNtfy(raw string) (*Ntfy, error) {
	if _, err := validateEndpoint(raw); err != nil {
		return nil, err
	}
	return &Ntfy{URL: raw}, nil
}

func (Ntfy) Name() string { return "ntfy" }

func (n Ntfy) Send(ctx context.Context, f Finding) error {
	return post(ctx, n.URL, "text/plain", []byte(Message(f)))
}

// Discord posts to an incoming webhook.
type Discord struct{ URL string }

func NewDiscord(raw string) (*Discord, error) {
	u, err := validateEndpoint(raw)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u.Host, "discord") {
		return nil, errNotDiscord
	}
	return &Discord{URL: raw}, nil
}

func (Discord) Name() string { return "discord" }

func (d Discord) Send(ctx context.Context, f Finding) error {
	return post(ctx, d.URL, "application/json",
		jsonBody(map[string]any{"content": Message(f)}))
}

// Slack posts to an incoming webhook.
type Slack struct{ URL string }

func NewSlack(raw string) (*Slack, error) {
	u, err := validateEndpoint(raw)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u.Host, "slack.com") {
		return nil, errNotSlack
	}
	return &Slack{URL: raw}, nil
}

func (Slack) Name() string { return "slack" }

func (s Slack) Send(ctx context.Context, f Finding) error {
	return post(ctx, s.URL, "application/json",
		jsonBody(map[string]any{"text": Message(f)}))
}

type notifyError string

func (e notifyError) Error() string { return string(e) }

const (
	errNotDiscord = notifyError("that does not look like a Discord webhook URL")
	errNotSlack   = notifyError("that does not look like a Slack webhook URL")
)

// isPrivateHost reports whether a host is on a local network, which is the only
// case where plain HTTP is accepted.
func isPrivateHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}
