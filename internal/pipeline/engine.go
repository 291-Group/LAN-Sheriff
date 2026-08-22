package pipeline

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/capture"
	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// FlushInterval is how often accumulated flow changes are written to the store.
// Writing every observation individually would be pointless churn: a flow that
// is merely still open produces one row update either way.
const FlushInterval = 2 * time.Second

// DomainLabeller categorizes a domain, e.g. as a tracker or telemetry endpoint.
// Satisfied by enrich.Labeller; an interface so the pipeline does not depend on
// the enrichment package.
type DomainLabeller interface {
	Category(domain string) (string, bool)
}

// Engine runs the capture sources and moves what they produce through the
// normalizer into the store and out to connected dashboards.
type Engine struct {
	Store   *store.Store
	Bus     *Bus
	Sources []capture.Source
	// Labeller is optional. Without one, lookups are recorded unlabelled.
	Labeller DomainLabeller

	norm   *Normalizer
	events chan types.RawEvent

	mu         sync.Mutex
	pending    map[string]types.Flow          // flow key -> latest state
	seenIPs    map[string]endpointSightingRec // ip -> most recent sighting
	pendingDNS []types.DNSEvent
	health     healthTracker

	// OnSighting receives device identity learned by a capture source, such as
	// the hostname and vendor in a DHCP request. Set by the caller so the
	// pipeline does not need to know about the discovery store.
	OnSighting func(types.Sighting)
}

// Health reports whether observations are reaching storage.
func (e *Engine) Health() Health { return e.health.snapshot() }

type endpointSightingRec struct {
	internal bool
	seen     time.Time
}

// NewEngine builds the pipeline.
func NewEngine(st *store.Store, bus *Bus, sources []capture.Source) *Engine {
	return &Engine{
		Store:   st,
		Bus:     bus,
		Sources: sources,
		norm:    NewNormalizer(),
		events:  make(chan types.RawEvent, 64),
		pending: make(map[string]types.Flow),
		seenIPs: make(map[string]endpointSightingRec),
	}
}

// Run starts every available source and processes events until ctx is done.
func (e *Engine) Run(ctx context.Context) error {
	// This host is registered by the caller before the pipeline starts, through
	// the same identity model discovery uses. Writing a device row here as well
	// produced two records for this machine, one from each writer, differing
	// only in how they spelled the hardware address.

	started := 0
	for _, src := range e.Sources {
		if !src.Capabilities().Available {
			slog.Info("capture source unavailable",
				"source", src.Name(), "hint", src.Capabilities().Hint)
			continue
		}
		if err := src.Start(ctx, e.events); err != nil {
			// A source that fails to start is reported, not fatal: the app must
			// come up regardless of what it can or cannot observe.
			slog.Warn("capture source failed to start", "source", src.Name(), "err", err)
			continue
		}
		slog.Info("capture source started", "source", src.Name())
		started++
	}
	if started == 0 {
		slog.Warn("no capture sources running; the dashboard will be empty")
	}

	flush := time.NewTicker(FlushInterval)
	defer flush.Stop()

	for {
		select {
		case <-ctx.Done():
			e.flush(context.WithoutCancel(ctx))
			for _, src := range e.Sources {
				src.Stop()
			}
			return ctx.Err()
		case ev := <-e.events:
			e.handle(ev)
		case <-flush.C:
			e.flush(ctx)
		}
	}
}

func (e *Engine) handle(ev types.RawEvent) {
	switch ev.Kind {
	case types.KindDNS:
		if ev.DNS != nil {
			e.recordDNS(ev.DNS)
			e.Bus.Publish(Message{Type: "dns", Data: ev.DNS})
		}
		return
	case types.KindSighting:
		if ev.Sighting != nil && e.OnSighting != nil {
			e.OnSighting(*ev.Sighting)
		}
		return
	case types.KindDevice:
		if ev.Device != nil {
			e.Bus.Publish(Message{Type: "device", Data: ev.Device})
		}
		return
	}

	for _, fe := range e.norm.Apply(ev) {
		e.record(fe)
		// Only opens and closes go out live. Publishing every "still open" tick
		// for every flow would flood the socket with nothing new to say.
		if fe.Phase != PhaseUpdate {
			e.Bus.Publish(Message{Type: "flow", Data: flowMessage{
				Phase: string(fe.Phase),
				Flow:  fe.Flow,
			}})
		}
	}
}

type flowMessage struct {
	Phase string     `json:"phase"`
	Flow  types.Flow `json:"flow"`
}

// recordDNS labels a lookup and stages it for the next flush.
//
// Labelling happens here rather than at query time so the category is stored
// with the observation, which keeps the feed cheap to read and means a lookup's
// label reflects the lists as they were when it happened.
func (e *Engine) recordDNS(ev *types.DNSEvent) {
	d := *ev
	if e.Labeller != nil && d.Flagged == "" {
		if cat, ok := e.Labeller.Category(d.QName); ok {
			d.Flagged = cat
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// Bound the buffer: a very busy resolver could otherwise outrun the flush
	// interval and grow this without limit.
	if len(e.pendingDNS) < 10000 {
		e.pendingDNS = append(e.pendingDNS, d)
	}
}

// record stages a flow change for the next flush.
func (e *Engine) record(fe FlowEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	f := fe.Flow
	e.pending[storeKey(f)] = f

	note := func(ip string, ts time.Time, internal bool) {
		if _, err := netip.ParseAddr(ip); err != nil {
			return
		}
		if prev, ok := e.seenIPs[ip]; ok && prev.seen.After(ts) {
			return
		}
		e.seenIPs[ip] = endpointSightingRec{internal: internal, seen: ts}
	}

	// **Which end is ours is a property of the direction, not of the address.**
	//
	// On IPv4 the two agreed, so reading it off the address worked: our side was
	// RFC 1918 and the far side was not. IPv6 has no NAT. This machine's own
	// address is globally routable and identical in form to a destination, so it
	// was recorded as one, enriched as one, and counted as one. macOS and Windows
	// rotate temporary addresses for privacy, which means a fresh phantom
	// destination appeared every time the address changed and the count grew for
	// as long as the install lived.
	//
	// On a router running Patrol Mode the same is true of every device on the
	// LAN, because their addresses are global too.
	//
	// The far side is still read from the address: a flow out to a private
	// address is a local service, not a destination on the internet.
	byForm := func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		return err == nil && netutil.IsInternal(addr)
	}
	srcInternal, dstInternal := byForm(f.SrcIP), byForm(f.DstIP)
	switch f.Direction {
	case types.DirOut:
		srcInternal = true // whoever opened it is on our side of the network
	case types.DirIn:
		dstInternal = true // we are the one being reached
	case types.DirInternal:
		srcInternal, dstInternal = true, true
	}
	note(f.DstIP, f.TSLast, dstInternal)
	note(f.SrcIP, f.TSLast, srcInternal)
}

func storeKey(f types.Flow) string {
	return f.Key.String() + "|" + f.TSStart.String()
}

// flush writes staged changes. Endpoints are written before flows so that the
// join behind the Watchtower query never sees a flow whose destination row does
// not exist yet.
func (e *Engine) flush(ctx context.Context) {
	e.mu.Lock()
	flows := make([]types.Flow, 0, len(e.pending))
	for _, f := range e.pending {
		flows = append(flows, f)
	}
	e.pending = make(map[string]types.Flow, len(e.pending))
	seen := e.seenIPs
	e.seenIPs = make(map[string]endpointSightingRec, len(seen))
	dnsEvents := e.pendingDNS
	e.pendingDNS = nil
	e.mu.Unlock()

	if len(seen) > 0 {
		batch := make(map[string]store.EndpointSighting, len(seen))
		for ip, s := range seen {
			batch[ip] = store.Sighting(s.internal, s.seen)
		}
		if err := e.Store.TouchEndpoints(ctx, batch); err != nil {
			slog.Warn("endpoint write failed", "err", err)
		}
	}
	if len(flows) > 0 {
		if err := e.Store.WriteFlows(ctx, flows); err != nil {
			e.health.failed(err)
			// Error rather than warning, and repeated rather than rate-limited:
			// this means observations are being discarded, which is the most
			// serious thing that can go wrong short of not starting.
			slog.Error("flows are not being recorded", "err", err,
				"consecutive_failures", e.health.snapshot().Consecutive)
		} else {
			e.health.succeeded()
		}
	}
	if len(dnsEvents) > 0 {
		if err := e.Store.WriteDNS(ctx, dnsEvents); err != nil {
			slog.Warn("dns write failed", "err", err)
		}
	}
}

// ActiveFlows returns the flows currently believed open.
func (e *Engine) ActiveFlows() []types.Flow { return e.norm.Active() }
