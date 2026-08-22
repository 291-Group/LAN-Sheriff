package discover

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The discovery service: the three passive sources running together.
//
// None of this needs privilege. The neighbour table is an ordinary read, and
// joining a multicast group is an ordinary socket operation, so the Roster is
// populated for every user rather than only those who can grant packet-capture
// rights.

// NeighbourInterval is how often the neighbour table is re-read.
//
// The table is a kernel cache that changes on its own schedule, so polling is the
// only way to observe it. Ten seconds is frequent enough that a device appearing
// on the network shows up promptly, and cheap enough to be irrelevant: the read
// is a few kilobytes and no packets are sent.
const NeighbourInterval = 10 * time.Second

// Service runs the discovery sources and reports what they find.
type Service struct {
	// Out receives every sighting. Required.
	Out func(types.Sighting)
	// OnError is called when a source cannot start, so the UI can say which
	// capabilities are missing. Optional.
	OnError func(source string, err error)

	// Sweep enables the gentle sweep, which finds devices that never speak to
	// this machine. See sweep.go for what "gentle" is constrained to mean.
	Sweep bool

	mu      sync.Mutex
	started bool
	// recent suppresses repeat sightings; see emit.
	recent map[string]time.Time
	// active records which sources are running, for the capability report.
	active map[string]bool
}

// Start begins discovery and returns immediately.
//
// A source that cannot start is reported and skipped rather than failing the
// call. Discovery is a best-effort enrichment: a machine where multicast is
// firewalled should still get a Roster from the neighbour table.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.active = map[string]bool{}
	s.mu.Unlock()

	// Marked here rather than inside the goroutines. Active() was being read by
	// the caller the instant Start returned, before either goroutine had run,
	// so the startup log claimed discovery was running on mDNS and SSDP alone,
	// omitting the neighbour table, which is the source that finds the most.
	// A log that under-reports is a log that sends somebody looking in the
	// wrong place.
	s.markActive("neighbours")
	go s.pollNeighbours(ctx)
	if s.Sweep {
		s.markActive("sweep")
		go s.sweepLoop(ctx)
	}

	if err := ListenMDNS(ctx, func(a Advert) { s.emit(sightingFromAdvert(a)) }); err != nil {
		s.report("mdns", err)
	} else {
		s.markActive("mdns")
		go s.queryLoop(ctx)
	}
	if err := ListenSSDP(ctx, func(a Advert) { s.emit(sightingFromAdvert(a)) }); err != nil {
		s.report("ssdp", err)
	} else {
		s.markActive("ssdp")
	}
}

// Active reports which discovery sources are running.
func (s *Service) Active() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name := range s.active {
		out = append(out, name)
	}
	return out
}

func (s *Service) markActive(name string) {
	s.mu.Lock()
	s.active[name] = true
	s.mu.Unlock()
}

func (s *Service) report(source string, err error) {
	if s.OnError != nil {
		s.OnError(source, err)
	}
}

// queryLoop prompts devices to announce themselves, so a freshly opened Roster
// has names in it rather than filling in over the following quarter of an hour.
func (s *Service) queryLoop(ctx context.Context) {
	// The listener needs a moment to be ready before answers start arriving;
	// without it the responses to the first query are missed.
	select {
	case <-ctx.Done():
		return
	case <-time.After(500 * time.Millisecond):
	}

	if err := QueryMDNS(ctx); err != nil {
		s.report("mdns-query", err)
	}

	ticker := time.NewTicker(QueryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := QueryMDNS(ctx); err != nil {
				s.report("mdns-query", err)
			}
		}
	}
}

// SweepInterval is how often the gentle sweep repeats.
//
// Long, because its job is to find what passive observation misses, and a device
// that has been silent for fifteen minutes will still be there in another
// fifteen. The neighbour table is re-read far more often; this only has to keep
// it stocked.
const SweepInterval = 15 * time.Minute

// sweepLoop runs the gentle sweep, first after a short delay and then on a long
// interval.
func (s *Service) sweepLoop(ctx context.Context) {
	// Passive discovery goes first. Most devices are found without sending
	// anything, and a Roster that fills from listening before it fills from
	// probing is the honest order to do this in.
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
	}

	run := func() {
		n, err := Sweep(ctx)
		if err != nil && ctx.Err() == nil {
			s.report("sweep", err)
			return
		}
		_ = n
	}
	run()

	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// pollNeighbours re-reads the OS table on a ticker.
func (s *Service) pollNeighbours(ctx context.Context) {
	// Read once immediately: waiting a full interval before the Roster shows
	// anything makes a fresh install look broken.
	s.sweepNeighbours(ctx)

	ticker := time.NewTicker(NeighbourInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepNeighbours(ctx)
		}
	}
}

func (s *Service) sweepNeighbours(ctx context.Context) {
	entries, err := Neighbours()
	if err != nil {
		s.report("neighbours", err)
		return
	}
	for _, n := range entries {
		// A device on a container bridge or VPN is not on the user's network in
		// any sense they would recognise, and listing one makes the Roster less
		// trustworthy rather than more complete.
		if n.Virtual {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.emit(types.Sighting{
			MAC:    n.MAC,
			IP:     n.Addr.String(),
			Vendor: Vendor(n.MAC),
			IsSelf: n.Self,
			Source: "neighbour",
			SeenAt: n.SeenAt,
		})
	}
}

// sightingFromAdvert converts a multicast announcement into a sighting.
//
// An advert carries no hardware address, it arrives over IP, and the sender's
// MAC is not visible to a socket. The address is what ties it to a neighbour-table
// entry, which is exactly the merge case the store's identity model handles.
func sightingFromAdvert(a Advert) types.Sighting {
	return types.Sighting{
		IP:       a.Addr.Addr().String(),
		Hostname: a.Hostname,
		Name:     a.Name,
		Model:    a.Model,
		Services: a.Services,
		Source:   a.Source,
		SeenAt:   a.SeenAt,
	}
}

// Coalescing repeat sightings.
//
// A chatty network re-announces the same facts constantly: a device may send the
// same mDNS record every few seconds, and the neighbour table is re-read on a
// ticker whether or not anything changed. Writing each one straight through would
// mean a database transaction per packet to record that nothing is different.
//
// So an identical sighting is dropped unless its cooldown has elapsed. The
// cooldown still has to fire regularly, because "last seen" is what decides
// whether a device is shown as online.
const sightingCooldown = 45 * time.Second

// emit passes a sighting on unless an identical one was reported recently.
func (s *Service) emit(sg types.Sighting) {
	key := sightingKey(sg)

	s.mu.Lock()
	if s.recent == nil {
		s.recent = map[string]time.Time{}
	}
	last, seen := s.recent[key]
	now := time.Now()
	if seen && now.Sub(last) < sightingCooldown {
		s.mu.Unlock()
		return
	}
	s.recent[key] = now
	// Bound the map. A network large enough to overflow this is one where the
	// oldest entries are no longer worth suppressing anyway.
	if len(s.recent) > 4096 {
		for k, t := range s.recent {
			if now.Sub(t) > sightingCooldown {
				delete(s.recent, k)
			}
		}
	}
	s.mu.Unlock()

	s.Out(sg)
}

// sightingKey identifies a sighting by its content, so that a genuinely new fact
// is never suppressed while a repeat of an old one is.
func sightingKey(sg types.Sighting) string {
	return strings.Join(append([]string{
		sg.Source, sg.MAC, sg.IP, sg.Hostname, sg.Name, sg.Model,
	}, sg.Services...), "\x00")
}
