package enrich

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Domain labelling.
//
// LAN Sheriff labels; it does not block. A domain matching a tracker list is
// shown as a tracker and the lookup proceeds exactly as it would have. That is
// the whole difference between this and Pi-hole, and it is deliberate: the
// product reveals so the user can decide, rather than deciding for them.
//
// The lists are the same public ones an ad-blocker would use, read only for
// their names. Nothing is sent to them, and the label is stored alongside the
// lookup rather than replacing it.

// Category names, kept short because they appear in a dense feed.
const (
	CategoryTracker   = "tracker"
	CategoryAds       = "ads"
	CategoryTelemetry = "telemetry"
	CategoryMalware   = "malware"
)

// listSource is one list to fetch and the category it assigns.
type listSource struct {
	name     string
	url      string
	category string
}

// The lists shipped with the product. All are widely used, freely available, and
// distributed in hosts-file or plain-domain form.
//
// Deliberately few. A comprehensive blocklist would label most of the internet,
// which turns a useful signal into noise; these cover the categories a person
// actually wants pointed out.
var defaultLists = []listSource{
	{
		name:     "stevenblack-ads-trackers",
		url:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
		category: CategoryAds,
	},
	{
		name:     "urlhaus-malware",
		url:      "https://urlhaus.abuse.ch/downloads/hostfile/",
		category: CategoryMalware,
	},
}

// Labeller matches domains against category lists.
type Labeller struct {
	dir    string
	client *http.Client
	lists  []listSource
	maxAge time.Duration

	mu     sync.RWMutex
	labels map[string]string // domain -> category
	loaded bool
}

// NewLabeller returns a labeller storing its list copies under dir.
func NewLabeller(dir string) *Labeller {
	return &Labeller{
		dir:    dir,
		client: &http.Client{Timeout: 3 * time.Minute},
		lists:  defaultLists,
		// Lists change daily but a day-old copy is perfectly serviceable, and
		// refetching on every start would be rude to the people hosting them.
		maxAge: 7 * 24 * time.Hour,
		labels: make(map[string]string),
	}
}

// Ready reports whether any list has been loaded.
func (l *Labeller) Ready() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.loaded && len(l.labels) > 0
}

// Size reports how many domains are labelled.
func (l *Labeller) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.labels)
}

// Category returns the label for a domain, checking parent domains too.
//
// A list naming "doubleclick.net" should also label
// "stats.g.doubleclick.net", so the lookup walks up the labels rather than
// requiring an exact match. Walking up also keeps the table far smaller than
// enumerating every subdomain would.
func (l *Labeller) Category(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return "", false
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	if cat, ok := l.labels[domain]; ok {
		return cat, true
	}
	// Walk up: a.b.example.com -> b.example.com -> example.com
	for i := 0; i < len(domain); i++ {
		if domain[i] != '.' {
			continue
		}
		if cat, ok := l.labels[domain[i+1:]]; ok {
			return cat, true
		}
	}
	return "", false
}

// Ensure loads every list, fetching any that are missing or stale.
//
// Designed to run in the background: a failure is logged and swallowed, because
// an unavailable list means lookups go unlabelled, not that anything breaks.
func (l *Labeller) Ensure(ctx context.Context) {
	merged := make(map[string]string, 1<<16)

	for _, src := range l.lists {
		domains, err := l.load(ctx, src)
		if err != nil {
			slog.Warn("could not load domain list",
				"list", src.name, "err", err,
				"effect", "lookups will not carry this label until it succeeds")
			continue
		}
		for _, d := range domains {
			// First list to claim a domain wins, so a malware label is not
			// downgraded to "ads" by a later list.
			if _, exists := merged[d]; !exists {
				merged[d] = src.category
			}
		}
		slog.Info("domain list ready", "list", src.name, "domains", len(domains))
	}

	if len(merged) == 0 {
		return
	}
	l.mu.Lock()
	l.labels = merged
	l.loaded = true
	l.mu.Unlock()
}

func (l *Labeller) load(ctx context.Context, src listSource) ([]string, error) {
	path := filepath.Join(l.dir, "list-"+src.name+".txt")

	if data, err := os.ReadFile(path); err == nil && fileAge(path) < l.maxAge {
		return parseDomainList(strings.NewReader(string(data))), nil
	}

	body, err := l.fetch(ctx, src.url)
	if err != nil {
		// Fall back to a stale copy rather than losing the label entirely.
		if data, rerr := os.ReadFile(path); rerr == nil {
			return parseDomainList(strings.NewReader(string(data))), nil
		}
		return nil, err
	}

	if mkErr := os.MkdirAll(l.dir, 0o700); mkErr == nil {
		writeAtomic(path, body)
	}
	return parseDomainList(strings.NewReader(string(body))), nil
}

func (l *Labeller) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	// Cap the read: these lists are a few megabytes, and an unbounded read
	// would undermine the promise that storage stays bounded.
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// parseDomainList reads either a hosts file or a plain domain list.
//
// Both formats are common and the difference is only whether each line carries a
// leading address, so handling both avoids caring which a given list uses.
func parseDomainList(r io.Reader) []string {
	var out []string
	seen := make(map[string]struct{}, 1<<16)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		// Strip a trailing comment.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// A hosts line is "0.0.0.0 domain"; a plain list is just "domain".
		domain := fields[0]
		if len(fields) > 1 && isRedirectAddress(fields[0]) {
			domain = fields[1]
		}

		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if !plausibleDomain(domain) {
			continue
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

// isRedirectAddress reports whether a field is the null address a hosts file
// uses to sink a domain.
func isRedirectAddress(s string) bool {
	switch s {
	case "0.0.0.0", "127.0.0.1", "::", "::1":
		return true
	}
	return false
}

// plausibleDomain rejects the entries in these lists that are not domains:
// localhost aliases, bare labels, and anything with characters a hostname
// cannot contain.
func plausibleDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	switch d {
	case "localhost", "localhost.localdomain", "local", "broadcasthost":
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
