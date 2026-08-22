package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RDAP answers "who registered this address block", which is the detail a Rap
// Sheet needs and nothing else does.
//
// It is deliberately on-demand only: one lookup per address the user actually
// opens, never a sweep, and never anywhere near the ingest path. Every result is
// cached hard, because registration data changes on the order of years.
//
// Rather than trusting a third-party redirector, the correct RDAP service for an
// address is resolved from IANA's own bootstrap registry, which is the
// authoritative mapping of address ranges to the RIR that governs them.

const (
	ianaBootstrapV4 = "https://data.iana.org/rdap/ipv4.json"
	ianaBootstrapV6 = "https://data.iana.org/rdap/ipv6.json"

	bootstrapFileV4 = "rdap-bootstrap-v4.json"
	bootstrapFileV6 = "rdap-bootstrap-v6.json"

	// The bootstrap registry changes rarely; a month between refreshes is
	// generous and keeps this to roughly twelve requests a year.
	bootstrapMaxAge = 30 * 24 * time.Hour
)

// Registration is the subset of an RDAP response worth showing a person.
type Registration struct {
	Handle       string    `json:"handle,omitempty"`
	Name         string    `json:"name,omitempty"`
	Range        string    `json:"range,omitempty"`
	Country      string    `json:"country,omitempty"`
	Organization string    `json:"organization,omitempty"`
	Abuse        string    `json:"abuse,omitempty"`
	Registered   string    `json:"registered,omitempty"`
	Updated      string    `json:"updated,omitempty"`
	Source       string    `json:"source,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// RDAP resolves registration detail for individual addresses.
type RDAP struct {
	dir    string
	client *http.Client

	mu        sync.RWMutex
	bootstrap map[bool]*bootstrapIndex // keyed by isIPv6
	cache     map[string]Registration
}

// NewRDAP returns a resolver storing its bootstrap copies under dir.
func NewRDAP(dir string) *RDAP {
	return &RDAP{
		dir: dir,
		// Short: this runs while a user waits for a panel to fill in.
		client:    &http.Client{Timeout: 12 * time.Second},
		bootstrap: make(map[bool]*bootstrapIndex, 2),
		cache:     make(map[string]Registration),
	}
}

// bootstrapIndex maps address ranges to the RDAP service that governs them.
type bootstrapIndex struct {
	entries []bootstrapEntry
}

type bootstrapEntry struct {
	prefix  netip.Prefix
	service string
}

// The IANA file shape: services is a list of [ [cidr, ...], [url, ...] ].
type ianaBootstrap struct {
	Services [][][]string `json:"services"`
}

// Lookup returns registration detail for one address.
//
// It reports false rather than an error when nothing can be found: a missing
// registration is normal and is not worth surfacing as a failure.
func (r *RDAP) Lookup(ctx context.Context, ip string) (Registration, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Registration{}, false
	}

	r.mu.RLock()
	cached, hit := r.cache[ip]
	r.mu.RUnlock()
	if hit {
		// A negative result is cached too, so a query that found nothing is not
		// repeated on every panel open.
		return cached, cached.Handle != "" || cached.Name != ""
	}

	service, ok := r.serviceFor(ctx, addr)
	if !ok {
		r.remember(ip, Registration{FetchedAt: time.Now()})
		return Registration{}, false
	}

	reg, ok := r.query(ctx, service, ip)
	reg.FetchedAt = time.Now()
	r.remember(ip, reg)
	return reg, ok
}

func (r *RDAP) remember(ip string, reg Registration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Bounded: the Rap Sheet is opened by hand, so this grows slowly, but an
	// unbounded map in a process meant to run for weeks is still wrong.
	if len(r.cache) > 4096 {
		r.cache = make(map[string]Registration, 512)
	}
	r.cache[ip] = reg
}

// serviceFor finds the RDAP base URL responsible for an address, loading the
// IANA bootstrap registry if it is not already in hand.
func (r *RDAP) serviceFor(ctx context.Context, addr netip.Addr) (string, bool) {
	v6 := addr.Is6() && !addr.Is4In6()

	r.mu.RLock()
	idx := r.bootstrap[v6]
	r.mu.RUnlock()

	if idx == nil {
		var err error
		idx, err = r.loadBootstrap(ctx, v6)
		if err != nil {
			return "", false
		}
		r.mu.Lock()
		r.bootstrap[v6] = idx
		r.mu.Unlock()
	}

	// Most specific match wins, exactly as routing would.
	best, bestBits := "", -1
	target := addr.Unmap()
	for _, e := range idx.entries {
		if e.prefix.Contains(target) && e.prefix.Bits() > bestBits {
			best, bestBits = e.service, e.prefix.Bits()
		}
	}
	return best, best != ""
}

func (r *RDAP) loadBootstrap(ctx context.Context, v6 bool) (*bootstrapIndex, error) {
	name, url := bootstrapFileV4, ianaBootstrapV4
	if v6 {
		name, url = bootstrapFileV6, ianaBootstrapV6
	}
	path := filepath.Join(r.dir, name)

	data, err := os.ReadFile(path)
	if fresh := err == nil && fileAge(path) < bootstrapMaxAge; !fresh {
		if fetched, ferr := r.fetch(ctx, url); ferr == nil {
			data = fetched
			if mkErr := os.MkdirAll(r.dir, 0o700); mkErr == nil {
				writeAtomic(path, fetched)
			}
		} else if err != nil {
			// Nothing on disk and the fetch failed.
			return nil, ferr
		}
	}

	var raw ianaBootstrap
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse rdap bootstrap: %w", err)
	}

	idx := &bootstrapIndex{}
	for _, svc := range raw.Services {
		if len(svc) < 2 {
			continue
		}
		var service string
		for _, u := range svc[1] {
			// Prefer HTTPS; an RDAP query over plain HTTP would be a poor look
			// for this particular product.
			if strings.HasPrefix(u, "https://") {
				service = u
				break
			}
		}
		if service == "" {
			continue
		}
		for _, cidr := range svc[0] {
			// The v4 file lists bare prefixes like "8" meaning 8.0.0.0/8.
			if !strings.Contains(cidr, "/") && !strings.Contains(cidr, ":") {
				cidr += ".0.0.0/8"
			}
			if p, err := netip.ParsePrefix(cidr); err == nil {
				idx.entries = append(idx.entries, bootstrapEntry{prefix: p, service: service})
			}
		}
	}
	if len(idx.entries) == 0 {
		return nil, fmt.Errorf("rdap bootstrap contained no usable entries")
	}
	return idx, nil
}

func (r *RDAP) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// rdapResponse is the part of the RDAP schema this needs. The format carries a
// great deal more; none of the rest belongs in a UI.
type rdapResponse struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	Country      string `json:"country"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Events       []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
}

func (r *RDAP) query(ctx context.Context, service, ip string) (Registration, bool) {
	url := strings.TrimSuffix(service, "/") + "/ip/" + ip

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Registration{}, false
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := r.client.Do(req)
	if err != nil {
		return Registration{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Registration{}, false
	}

	var raw rdapResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&raw); err != nil {
		return Registration{}, false
	}

	reg := Registration{
		Handle:  raw.Handle,
		Name:    raw.Name,
		Country: raw.Country,
		Source:  serviceHost(service),
	}
	if raw.StartAddress != "" && raw.EndAddress != "" {
		reg.Range = raw.StartAddress + " to " + raw.EndAddress
	}
	for _, e := range raw.Events {
		switch e.Action {
		case "registration":
			reg.Registered = shortDate(e.Date)
		case "last changed":
			reg.Updated = shortDate(e.Date)
		}
	}
	for _, ent := range raw.Entities {
		name, email := vcardNameAndEmail(ent.VCardArray)
		if hasRole(ent.Roles, "abuse") && email != "" && reg.Abuse == "" {
			reg.Abuse = email
		}
		if reg.Organization == "" && name != "" &&
			(hasRole(ent.Roles, "registrant") || hasRole(ent.Roles, "administrative")) {
			reg.Organization = name
		}
	}
	return reg, reg.Handle != "" || reg.Name != ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardNameAndEmail digs the full name and email out of a jCard.
//
// The format is an array of ["property", {params}, "type", value] tuples nested
// two levels deep, which is why this is fiddly rather than a struct tag.
func vcardNameAndEmail(vcard []any) (name, email string) {
	if len(vcard) < 2 {
		return "", ""
	}
	props, ok := vcard[1].([]any)
	if !ok {
		return "", ""
	}
	for _, p := range props {
		field, ok := p.([]any)
		if !ok || len(field) < 4 {
			continue
		}
		key, _ := field[0].(string)
		value, _ := field[3].(string)
		switch strings.ToLower(key) {
		case "fn":
			if name == "" {
				name = value
			}
		case "email":
			if email == "" {
				email = value
			}
		}
	}
	return name, email
}

// shortDate keeps the day and drops the time, which is all that is meaningful
// for a registration event.
func shortDate(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02")
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func serviceHost(service string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(service, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	return s
}

func fileAge(path string) time.Duration {
	fi, err := os.Stat(path)
	if err != nil {
		return 1 << 62
	}
	return time.Since(fi.ModTime())
}
