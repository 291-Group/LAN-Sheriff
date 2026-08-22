// Package enrich decorates observed endpoints with the detail that makes them
// legible: where they are, who owns them, and what they are called.
//
// Enrichment is deliberately off the ingest path. A flow is stored and shown
// the moment it is seen; its location and organization arrive shortly after and
// the UI fills them in. Nothing waits on a lookup.
package enrich

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Sink is the part of the store the enricher needs.
type Sink interface {
	PendingEnrichment(ctx context.Context, limit int) ([]string, error)
	SaveEnrichment(ctx context.Context, e types.Endpoint) error
	RequeueUnresolved(ctx context.Context) (int64, error)
}

// Options configures the enricher.
type Options struct {
	Workers    int
	BatchSize  int
	Interval   time.Duration
	CacheSize  int
	ReverseDNS bool
}

// DefaultOptions are tuned to keep a Pi comfortable.
func DefaultOptions() Options {
	return Options{
		Workers:    4,
		BatchSize:  128,
		Interval:   2 * time.Second,
		CacheSize:  8192,
		ReverseDNS: true,
	}
}

// Enricher resolves endpoint detail in the background.
type Enricher struct {
	opts  Options
	sink  Sink
	geo   *geoDB
	mgr   *Manager
	cache *cache

	// rdnsLimit bounds concurrent PTR lookups so a burst of new endpoints
	// cannot turn into a burst of DNS traffic, which would be a poor look for
	// a tool whose whole point is watching what you send out.
	rdnsLimit chan struct{}
	// rdnsTokens is a token bucket over and above the concurrency limit.
	// Concurrency alone bounds how many lookups run at once, not how many run
	// per minute; on a busy network that difference is thousands of queries.
	rdnsTokens chan struct{}
	// rdnsMisses remembers addresses with no PTR record. Most of the internet
	// has none, so without this every pass retries every failure forever.
	rdnsMisses *missCache

	// started records when the enricher began, so that a dataset which never
	// arrives (no internet) eventually stops holding enrichment hostage.
	started time.Time
}

// datasetGrace is how long to wait for the full dataset set before enriching
// with whatever is available. An offline machine should still get reverse DNS
// and its own labels rather than nothing at all.
const datasetGrace = 2 * time.Minute

func (e *Enricher) datasetsGaveUp() bool {
	return time.Since(e.started) > datasetGrace
}

// New builds an enricher over the given dataset manager.
func New(sink Sink, mgr *Manager, opts Options) *Enricher {
	if opts.Workers <= 0 {
		opts = DefaultOptions()
	}
	e := &Enricher{
		started:    time.Now(),
		opts:       opts,
		sink:       sink,
		mgr:        mgr,
		geo:        newGeoDB(mgr),
		cache:      newCache(opts.CacheSize),
		rdnsLimit:  make(chan struct{}, 8),
		rdnsTokens: make(chan struct{}, rdnsBurst),
		rdnsMisses: newMissCache(4096, rdnsMissTTL),
	}
	for i := 0; i < rdnsBurst; i++ {
		e.rdnsTokens <- struct{}{}
	}
	return e
}

// Reverse-DNS budget. The burst covers opening a busy view without stalling,
// and the refill rate keeps the long-run cost modest.
const (
	rdnsBurst   = 24
	rdnsRefill  = 150 * time.Millisecond
	rdnsMissTTL = 6 * time.Hour
)

// RunReverseDNSBudget refills the reverse-DNS token bucket until ctx is done.
func (e *Enricher) runRDNSBudget(ctx context.Context) {
	t := time.NewTicker(rdnsRefill)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			select {
			case e.rdnsTokens <- struct{}{}:
			default: // bucket full
			}
		}
	}
}

// Ready reports whether location lookups are currently possible.
func (e *Enricher) Ready() bool { return e.geo.Ready() }

// Close releases the datasets.
func (e *Enricher) Close() { e.geo.Close() }

// Run works the enrichment queue until the context is cancelled.
func (e *Enricher) Run(ctx context.Context) {
	// The datasets may land after startup, so keep retrying the open until they
	// do, then stop checking.
	go e.watchDatasets(ctx)
	go e.runRDNSBudget(ctx)

	t := time.NewTicker(e.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.drain(ctx)
		}
	}
}

func (e *Enricher) watchDatasets(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		if e.geo.Complete() {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !e.geo.Reload() {
				continue
			}
			// Something new loaded. Anything already resolved against the
			// smaller set deserves another look.
			n, err := e.sink.RequeueUnresolved(ctx)
			if err != nil {
				slog.Debug("requeue after dataset load failed", "err", err)
				continue
			}
			if n > 0 {
				slog.Info("re-resolving endpoints against newly available data", "endpoints", n)
				e.cache.reset()
			}
		}
	}
}

// drain enriches one batch of pending endpoints.
func (e *Enricher) drain(ctx context.Context) {
	// Resolving before the datasets have landed would stamp endpoints as
	// enriched while knowing nothing about them. Better to wait: the flows are
	// already stored and shown, only their labels are pending.
	if !e.geo.Complete() && !e.datasetsGaveUp() {
		return
	}

	ips, err := e.sink.PendingEnrichment(ctx, e.opts.BatchSize)
	if err != nil {
		slog.Debug("enrichment queue read failed", "err", err)
		return
	}
	if len(ips) == 0 {
		return
	}

	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < e.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				ep, ok := e.Resolve(ctx, ip)
				if !ok {
					continue
				}
				if err := e.sink.SaveEnrichment(ctx, ep); err != nil {
					slog.Debug("save enrichment failed", "ip", ip, "err", err)
				}
			}
		}()
	}
	for _, ip := range ips {
		select {
		case work <- ip:
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return
		}
	}
	close(work)
	wg.Wait()
}

// Resolve enriches a single address. It reports false only when the address is
// unparseable; an address we simply know nothing about still returns a record,
// so it is not retried forever.
func (e *Enricher) Resolve(ctx context.Context, ip string) (types.Endpoint, bool) {
	if ep, ok := e.cache.get(ip); ok {
		return ep, true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return types.Endpoint{}, false
	}

	ep := types.Endpoint{IP: ip}
	g := e.geo.Lookup(addr)
	ep.Country, ep.CountryName, ep.City = g.Country, g.CountryName, g.City
	ep.Lat, ep.Lon = g.Lat, g.Lon
	ep.ASN, ep.Org = g.ASN, g.Org

	if e.opts.ReverseDNS {
		ep.RDNS = e.reverseDNS(ctx, ip)
	}

	e.cache.put(ip, ep)
	return ep, true
}

// reverseDNS does a best-effort PTR lookup. A failure is normal and silent:
// most addresses on the internet have no reverse record.
//
// Three things bound the cost, because a tool that watches your outbound
// traffic should not itself be a noticeable source of it: a concurrency limit,
// a token bucket on the rate, and a memory of which addresses have already come
// back empty.
func (e *Enricher) reverseDNS(ctx context.Context, ip string) string {
	if e.rdnsMisses.has(ip) {
		return ""
	}

	// Spend a token, but never block waiting for one: enrichment is background
	// work and a label arriving on the next pass is fine.
	select {
	case <-e.rdnsTokens:
	default:
		return ""
	}

	select {
	case e.rdnsLimit <- struct{}{}:
		defer func() { <-e.rdnsLimit }()
	case <-ctx.Done():
		return ""
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		e.rdnsMisses.add(ip)
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// missCache remembers lookups that found nothing, for a while.
//
// Entries expire rather than being permanent: a reverse record can be added
// later, and a tool that never re-checks would keep showing a bare address
// forever.
type missCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	items map[string]time.Time
}

func newMissCache(max int, ttl time.Duration) *missCache {
	return &missCache{max: max, ttl: ttl, items: make(map[string]time.Time, max)}
}

func (m *missCache) has(k string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.items[k]
	if !ok {
		return false
	}
	if time.Since(at) > m.ttl {
		delete(m.items, k)
		return false
	}
	return true
}

func (m *missCache) add(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.items) >= m.max {
		// Drop expired entries first; only clear wholesale if that frees nothing.
		for key, at := range m.items {
			if time.Since(at) > m.ttl {
				delete(m.items, key)
			}
		}
		if len(m.items) >= m.max {
			m.items = make(map[string]time.Time, m.max)
		}
	}
	m.items[k] = time.Now()
}

// cache is a small bounded map of resolved endpoints. Eviction is by insertion
// order rather than true LRU: enrichment results are cheap to recompute and the
// access pattern is dominated by recency anyway.
type cache struct {
	mu    sync.RWMutex
	max   int
	items map[string]types.Endpoint
	order []string
}

func newCache(max int) *cache {
	if max <= 0 {
		max = 4096
	}
	return &cache{max: max, items: make(map[string]types.Endpoint, max)}
}

func (c *cache) get(k string) (types.Endpoint, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.items[k]
	return v, ok
}

// reset empties the cache, so that endpoints resolved against an older, smaller
// dataset are looked up again rather than served from memory.
func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]types.Endpoint, c.max)
	c.order = c.order[:0]
}

func (c *cache) put(k string, v types.Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[k]; !exists {
		if len(c.order) >= c.max {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.items, oldest)
		}
		c.order = append(c.order, k)
	}
	c.items[k] = v
}
