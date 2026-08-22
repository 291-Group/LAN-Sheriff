// Package deputy implements Deputy Mode: watching this machine's own
// connections by reading the OS socket tables, with the owning process
// attached. It needs no elevated privilege, which is what makes it the
// zero-configuration default.
//
// Each OS gets its own sampler (see sample_*.go); everything above that is
// shared.
package deputy

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// DefaultInterval is how often the socket table is re-read. Fast enough that a
// short-lived connection is usually caught, slow enough to stay invisible in
// `top` on a Pi.
const DefaultInterval = 2 * time.Second

// Options configures the source.
type Options struct {
	Interval time.Duration
	// DeviceID is the identity of this host, stamped onto every connection.
	DeviceID string
}

// Source is the Deputy Mode capture source.
type Source struct {
	opts    Options
	sampler sampler

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}

	// initErr records why the sampler could not be created, so Capabilities can
	// explain the situation rather than the app failing to start.
	initErr error
	// sampleFailures counts consecutive failed samples; see emit.
	sampleFailures atomic.Int64
}

// New builds a Deputy Mode source. It never returns an error: if the platform
// sampler is unavailable, the source reports itself unavailable and the rest of
// the application carries on without it.
func New(opts Options) *Source {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	s := &Source{opts: opts, done: make(chan struct{})}
	sm, err := newSampler()
	if err != nil {
		s.initErr = err
		return s
	}
	s.sampler = sm
	return s
}

func (s *Source) Name() string { return "deputy" }

func (s *Source) Capabilities() types.Capabilities {
	c := types.Capabilities{
		Mode:     "deputy",
		Topology: "host",
	}
	if s.sampler == nil {
		c.Available = false
		c.Topology = "none"
		c.Hint = fmt.Sprintf("Deputy Mode is not available on %s yet: %v", runtime.GOOS, s.initErr)
		c.HintCode = types.HintDeputyUnsupported
		return c
	}
	c.Available = true
	c.HostEgress = true
	c.ProcessAttribution = true
	c.DeviceInventory = true // this host only
	c.ByteCounts = s.sampler.byteCounts()
	// Deputy Mode has no packet access, so it cannot read DNS off the wire. It
	// can, however, see that this host is *serving* DNS, the case where the
	// machine runs dnsmasq, Pi-hole or Unbound for the network. There the socket
	// table is enough to know a resolver is present, and Radio Chatter has a
	// legitimate source without any capture privilege at all.
	c.DNSFeed = s.servesDNS()
	c.Hint = "Deputy Mode shows this machine only. Patrol Mode adds every other device on the network, the DNS feed, and the full network map."
	c.HintCode = types.HintDeputyOnly
	return c
}

// Start begins polling. It returns immediately; observations arrive on out.
func (s *Source) Start(ctx context.Context, out chan<- types.RawEvent) error {
	if s.sampler == nil {
		return fmt.Errorf("deputy: %w", s.initErr)
	}

	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return fmt.Errorf("deputy: already started")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	done := s.done
	s.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(s.opts.Interval)
		defer t.Stop()

		// Sample once immediately so the map starts painting on launch rather
		// than after the first tick.
		s.emit(ctx, out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.emit(ctx, out)
			}
		}
	}()
	return nil
}

func (s *Source) emit(ctx context.Context, out chan<- types.RawEvent) {
	conns, err := s.sampler.sample()
	if err != nil {
		// A single failed sample is not fatal: the socket table can be
		// transiently unreadable, typically a process exiting mid-walk.
		//
		// A *run* of them is a different thing entirely, and must not be quiet.
		// A sampler that has stopped working produces exactly what a silent
		// network produces (nothing) so without this the dashboard would show
		// an idle machine rather than a broken one.
		n := s.sampleFailures.Add(1)
		if n == failureRunThreshold {
			slog.Error("the socket table cannot be read; this machine's connections are not being observed",
				"source", s.Name(), "consecutive_failures", n, "err", err)
		}
		return
	}
	if prev := s.sampleFailures.Swap(0); prev >= failureRunThreshold {
		slog.Info("the socket table is readable again", "source", s.Name(), "after_failures", prev)
	}
	if s.opts.DeviceID != "" {
		for i := range conns {
			conns[i].DeviceID = s.opts.DeviceID
		}
	}
	ev := types.RawEvent{
		Kind:     types.KindConnSnapshot,
		Source:   s.Name(),
		TS:       time.Now(),
		Snapshot: conns,
	}
	select {
	case out <- ev:
	case <-ctx.Done():
	}
}

// failureRunThreshold is how many consecutive failed samples count as broken
// rather than transient. At the default poll interval this is a few seconds of
// silence, which is short enough to be useful and long enough not to fire on a
// process exiting at an awkward moment.
const failureRunThreshold = 5

func (s *Source) Stop() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
	if s.sampler != nil {
		return s.sampler.close()
	}
	return nil
}

// servesDNS reports whether this host is listening on the DNS port, which means
// it is acting as a resolver for something.
//
// Checked live rather than cached: a resolver can be started or stopped while
// LAN Sheriff runs, and claiming a DNS feed that has since gone away would be
// worse than noticing late.
func (s *Source) servesDNS() bool {
	if s.sampler == nil {
		return false
	}
	conns, err := s.sampler.sample()
	if err != nil {
		return false
	}
	for _, c := range conns {
		if c.Listening && c.Src.Port() == 53 {
			return true
		}
	}
	return false
}

// sampler is the per-OS half of Deputy Mode: one call, the current socket table
// with owning processes attached.
type sampler interface {
	sample() ([]types.Conn, error)
	// byteCounts reports whether this platform's socket table carries per-
	// connection byte counters. Most do not, which is why the Watchtower falls
	// back to connection counts for arc weight in Deputy Mode.
	byteCounts() bool
	close() error
}
