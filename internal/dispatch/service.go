package dispatch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/netutil"
)

// The Dispatch service: one listener, one dialler per paired peer, and the state
// machine that keeps them alive. docs/DISPATCH-PROTOCOL.md §9.
//
// The demand this is written against is that **a peer disappearing is ordinary**,
// not an error. A laptop closes. A phone sleeps. None of that may block, stall
// or crash anything else, and in particular none of it may ever be on the path
// of an API request: the dashboard renders from the local store, and peer data
// is whatever has already been merged.

const (
	// backoffMin is the first reconnect delay.
	backoffMin = time.Second
	// backoffMax is the ceiling. Five minutes is long enough that a peer which
	// is switched off costs nothing, and short enough that one switched back on
	// is picked up without the user waiting.
	backoffMax = 5 * time.Minute
	// backoffJitter is the proportion of random spread applied to each delay.
	//
	// Not decoration. Two instances rebooted together, a power cut, a switch
	// restarting, otherwise retry in lockstep forever, each finding the other
	// not yet listening.
	backoffJitter = 0.2

	// greyAfter is how long without contact before a peer is shown as gone.
	greyAfter = 90 * time.Second

	// staleAfter is when a peer's merged data stops being presented as current.
	staleAfter = time.Hour

	// MaxPeers bounds the whole feature's resource use.
	MaxPeers = 8

	// summaryInterval is how often this instance offers its aggregates.
	//
	// Two minutes rather than continuously: buckets are hourly, so sending more
	// often only restates the same numbers, and the receiver replaces rather
	// than accumulates.
	summaryInterval = 2 * time.Minute

	// summaryWindow is how much history each send covers. Wider than the
	// interval so a missed send is repaired by the next one rather than leaving
	// a permanent gap.
	summaryWindow = 6 * time.Hour

	// PeerDataTTL is how long a peer's merged data is kept once it stops being
	// refreshed. Peer data is a cache, not a record.
	PeerDataTTL = 7 * 24 * time.Hour
)

// PeerRecord is what the service needs to know about a paired peer.
//
// A local type rather than the store's, so this package can be tested against a
// map and does not depend on the database.
type PeerRecord struct {
	PeerID    string
	PublicKey ed25519.PublicKey
	Label     string
	Suspended bool
	LastAddr  string
}

// Store is the persistence the service needs. Narrow on purpose: the service
// reads pairings and writes summaries, and can do nothing else.
type Store interface {
	DispatchPeers(ctx context.Context) ([]PeerRecord, error)
	MergeDispatchSummaries(ctx context.Context, peerID string, buckets []SummaryBucket, now time.Time) (int, error)
	AddDispatchPeer(ctx context.Context, p PairedPeer) error
	// LocalSummaries is what this instance offers its peers.
	LocalSummaries(ctx context.Context, since time.Time, limit int) ([]SummaryBucket, error)
	// SetDispatchPeerAddr records where a peer was last reached, so a peer whose
	// DHCP lease moved can still be dialled after a restart.
	SetDispatchPeerAddr(ctx context.Context, peerID, addr string) error

	// SetDispatchPeerLabelIfEmpty gives a peer the name it calls itself, and
	// only when this machine has none for it. A name chosen here always wins.
	SetDispatchPeerLabelIfEmpty(ctx context.Context, peerID, label string) error
	// ExpireDispatchSummaries drops peer data past its time to live.
	ExpireDispatchSummaries(ctx context.Context, ttl time.Duration, now time.Time) (int64, error)
}

// Config controls the service. The zero value is disabled, which is the point:
// nothing here starts unless somebody asked for it.
type Config struct {
	// Enabled must be set explicitly. There is no default-on path.
	Enabled bool
	// Listen is the address to accept peers on, host:port.
	Listen string
	// AllowPublic permits binding an address reachable from outside this
	// network. Off unless the operator insisted.
	AllowPublic bool
	// DataDir is where the identity key lives.
	DataDir string
}

// PeerState is a peer's live status, for display.
type PeerState struct {
	PeerID    string    `json:"peer_id"`
	Label     string    `json:"label,omitempty"`
	Connected bool      `json:"connected"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Addr      string    `json:"addr,omitempty"`
	// Status is "connected", "grey" or "suspended", the three things a person
	// needs to tell apart. "grey" means we cannot reach it, which is a different
	// statement from "it reports nothing", and conflating them would let a
	// silenced monitor look like a quiet network.
	Status string `json:"status"`
	// DataStale marks a peer we have not heard from for long enough that what it
	// last told us should not be presented as current.
	//
	// Separate from Status on purpose: a peer can be freshly reconnected and
	// still have nothing recent to show, and a peer can be unreachable while its
	// last hour of data is perfectly good. Collapsing the two would make the map
	// claim currency it does not have.
	DataStale bool `json:"data_stale,omitempty"`
}

// Service runs The Dispatch.
type Service struct {
	cfg   Config
	id    *Identity
	store Store
	log   *slog.Logger

	mu   sync.RWMutex
	live map[string]*Conn
	seen map[string]time.Time

	ln net.Listener
	wg sync.WaitGroup

	// The service owns its own cancellation rather than relying on the caller's
	// context. Stop() must be sufficient on its own: a shutdown that only works
	// when the caller happens to cancel first is a deadlock waiting for the
	// wrong defer order, and that is exactly how this was first written.
	cancel    context.CancelFunc
	stopOnce  sync.Once
	startedAt time.Time

	// pairing is the open invitation, if any. Guarded by mu. While it is
	// non-nil the listener admits an unpinned key, see pairingVerifier.
	pairing *PairingSession
}

// ErrDisabled is returned when the service is asked to start without being
// enabled.
var ErrDisabled = errors.New("dispatch: not enabled")

// New prepares the service, generating this instance's identity if needed.
//
// **Called only when the feature is enabled.** The key is created here rather
// than at startup so that an install which never turns peering on never has a
// private key on disk to steal.
func New(cfg Config, st Store, log *slog.Logger) (*Service, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	if log == nil {
		log = slog.Default()
	}
	if err := checkBindAddress(cfg.Listen, cfg.AllowPublic); err != nil {
		return nil, err
	}
	id, err := LoadIdentity(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg: cfg, id: id, store: st, log: log,
		live: map[string]*Conn{},
		seen: map[string]time.Time{},
	}, nil
}

// Identity exposes this instance's identity, for the pairing UI.
func (s *Service) Identity() *Identity { return s.id }

// listenPort is the port peers should dial us on.
func (s *Service) listenPort() int {
	if s.ln == nil {
		return 0
	}
	if a, ok := s.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// selfLabel is what this machine calls itself when introducing itself to a peer.
//
// The hostname, because a peer list of unnamed fingerprints is unusable and the
// operator should not have to name both ends by hand. Purely cosmetic: it is
// stored as a label and never used to decide anything.
// selfLabel is what this machine calls itself to its peers.
//
// The hostname, but not blindly. This name is the only thing standing between a
// reader and a 29-character fingerprint, and on the three commonest ways this
// software is installed the raw hostname is one of:
//
//	workshop-mac.local          macOS, with a suffix that is noise to a reader
//	ac382c079142        a container, whose hostname is its id and means nothing
//	localhost           a machine nobody has named, which names nothing
//
// So the suffixes come off and the useless answers are treated as no answer,
// which is honest: an empty label lets the other end fall back to something it
// can explain, rather than confidently displaying a container id as a name.
//
// Whatever survives is only a default. The operator can rename any peer, which
// is the real answer to a machine that cannot describe itself.
func selfLabel() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	h = strings.TrimSpace(h)
	for _, suffix := range []string{".local", ".localdomain", ".lan", ".home"} {
		h = strings.TrimSuffix(h, suffix)
	}
	switch strings.ToLower(h) {
	case "", "localhost", "unknown", "none":
		return ""
	}
	// A container id: twelve or sixty-four hex digits and nothing else. Docker
	// sets the hostname to it, and it is not a name, it is an address for a
	// thing that will not exist tomorrow.
	if isHexID(h) {
		return ""
	}
	return h
}

// isHexID reports whether s is only hex digits and long enough to be a machine
// identifier rather than a name somebody chose. Twelve is Docker's short id;
// the lower bound keeps real names like "ada" and "beef" out of it by requiring
// far more length than a word.
func isHexID(s string) bool {
	if len(s) != 12 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// checkBindAddress refuses an address reachable from outside the local network.
//
// This is the mitigation for A2 and it lives in code rather than documentation,
// because a warning in a README is not a control. The operator can override it,
// and is told exactly what they are agreeing to.
func checkBindAddress(listen string, allowPublic bool) error {
	if listen == "" {
		return errors.New("dispatch: no listen address")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("dispatch: listen address %q: %w", listen, err)
	}
	if allowPublic {
		return nil
	}
	// An unspecified address binds every interface, including any public one.
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf(
			"dispatch: refusing to listen on %q, which accepts connections on every interface. "+
				"Name the address on your local network instead, or pass --dispatch-allow-public "+
				"if this machine is genuinely meant to accept peers from the internet", listen)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname. Not resolved here, resolution can change under us, and
		// refusing something we cannot check would break legitimate setups.
		return nil
	}
	// netutil's classification rather than netip's IsPrivate, and the difference
	// is 100.64.0.0/10. The standard library calls that block public, because it
	// is not RFC 1918, but it is the carrier-grade NAT range and **it is the
	// range Tailscale assigns from**, so every tailnet address failed this check.
	//
	// The error a tailnet user got was not merely unhelpful, it was dangerous
	// advice: it told them their tailnet address was "reachable from the
	// internet" and instructed them to pass --dispatch-allow-public. That flag
	// really does permit an internet-reachable bind, and once it is in a systemd
	// unit or a compose file it stays there, so the next time the listen address
	// changes the guard is already switched off. Refusing something safe pushed
	// people into disabling the check that protects them.
	//
	// Reading it as internal is right for the other occupant of the block too: a
	// machine behind an ISP's carrier-grade NAT cannot be reached from the
	// internet either, since that is what the NAT is for.
	if !netutil.IsInternal(addr) {
		return fmt.Errorf(
			"dispatch: refusing to listen on %q, which is reachable from the internet. "+
				"The Dispatch is designed for machines on one local network; exposing it widens "+
				"the attack surface of a tool holding a record of your network. "+
				"Pass --dispatch-allow-public to override", host)
	}
	return nil
}

// Start begins listening and dialling. It returns once the listener is up;
// everything else runs in the background.
func (s *Service) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("dispatch: listen on %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	s.log.Info("dispatch listening",
		"addr", ln.Addr().String(), "peer_id", s.id.PeerID())

	// Derived, so the caller cancelling still stops us, but Stop() does not
	// depend on the caller ever doing so.
	ctx, s.cancel = context.WithCancel(ctx)
	s.startedAt = time.Now()

	s.wg.Add(5)
	go func() { defer s.wg.Done(); s.acceptLoop(ctx) }()
	go func() { defer s.wg.Done(); s.dialLoop(ctx) }()
	go func() { defer s.wg.Done(); s.expireLoop(ctx) }()
	// Relocation, so a peer whose address changed while it was offline can still
	// be found. Both halves only run while peering is on.
	go func() { defer s.wg.Done(); s.announce(ctx) }()
	go func() { defer s.wg.Done(); s.relocate(ctx) }()
	return nil
}

// expireLoop drops peer data that has stopped being refreshed.
//
// Peer data is a cache with a TTL, and a TTL nothing enforces is a comment. This
// existed as a documented property and an unused store method until an audit
// noticed nothing called it.
func (s *Service) expireLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n, err := s.store.ExpireDispatchSummaries(ctx, PeerDataTTL, now)
			if err != nil {
				s.log.Warn("dispatch cannot expire peer data", "err", err)
				continue
			}
			if n > 0 {
				s.log.Info("dispatch expired stale peer data", "rows", n)
			}
		}
	}
}

// Addr reports where the service is listening.
func (s *Service) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Stop closes the listener and every live connection, and waits.
func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		// Cancel first, so in-flight handshakes and the dial loop are already
		// unwinding by the time we wait for them.
		if s.cancel != nil {
			s.cancel()
		}
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.mu.Lock()
		for _, c := range s.live {
			c.SayGoodbye("shutting down")
		}
		s.live = map[string]*Conn{}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

// acceptLoop admits connections from paired peers.
func (s *Service) acceptLoop(ctx context.Context) {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("dispatch accept failed", "err", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveInbound(ctx, raw)
		}()
	}
}

// serveInbound authenticates and runs one accepted connection.
func (s *Service) serveInbound(ctx context.Context, raw net.Conn) {
	peers, err := s.store.DispatchPeers(ctx)
	if err != nil {
		s.log.Warn("dispatch cannot read pairings", "err", err)
		_ = raw.Close()
		return
	}
	keys := make([]ed25519.PublicKey, 0, len(peers))
	for _, p := range peers {
		keys = append(keys, p.PublicKey)
	}

	cfg, err := ServerTLS(s.id, pairingVerifier(keys, s.hasPairingSession))
	if err != nil {
		s.log.Error("dispatch server config", "err", err)
		_ = raw.Close()
		return
	}
	conn, err := Handshake(ctx, raw, cfg, true)
	if err != nil {
		// Expected and frequent: this is what a stranger's connection looks
		// like. Logged at debug so a scanned network does not fill the log.
		s.log.Debug("dispatch rejected a connection",
			"remote", raw.RemoteAddr().String(), "err", err)
		return
	}

	// **Decided by what the caller asks for, not by whether we recognise it.**
	//
	// This used to route on the key alone: a known key was always a peer
	// reconnecting, and only an unknown one could pair. That is wrong in the
	// ordinary case where a machine has been unpaired here but still has us
	// paired, because unpairing is local to the machine that does it. That
	// machine dials in to pair again, is recognised, is handed to the session
	// loop, and receives a goodbye. The dashboard on the other end reported
	// "not showing a pairing code" while a window was open and the code was
	// fresh, which cost an evening.
	//
	// The first message already says which is wanted, so read it and put it
	// back for whichever handler takes the connection. A pair request is only
	// honoured while a window is open, so an already-paired peer cannot force
	// re-pairing: the operator here has to have asked for it.
	first, err := conn.Receive()
	if err != nil {
		s.log.Debug("dispatch: no opening message", "err", err)
		conn.Close()
		return
	}
	conn.Unread(first)

	if first.Type == TypePairRequest && s.hasPairingSession() {
		s.completePairing(ctx, conn)
		return
	}
	if !knownKey(keys, conn.PublicKey()) {
		// An unknown key that is not pairing has nothing to say to us.
		s.completePairing(ctx, conn)
		return
	}
	s.run(ctx, conn)
}

// knownKey reports whether a key is already paired.
func knownKey(keys []ed25519.PublicKey, got ed25519.PublicKey) bool {
	return PinnedToAny(keys)(got) == nil
}

// completePairing runs the displaying side of the pairing exchange.
func (s *Service) completePairing(ctx context.Context, conn *Conn) {
	defer conn.Close()

	ps := s.takePairing()
	if ps == nil {
		s.log.Debug("dispatch: unpinned connection with no pairing window open")
		return
	}
	peer, err := s.id.AcceptPairing(conn, ps, selfLabel(), s.listenPort(), time.Now())
	if err != nil {
		// Logged at warn, not debug: somebody produced a wrong code against an
		// open window, which is either a mistyped code or an attempt, and the
		// operator is standing at the screen either way.
		s.log.Warn("dispatch pairing failed", "err", err)
		return
	}
	if err := s.store.AddDispatchPeer(ctx, peer); err != nil {
		s.log.Error("dispatch cannot record a pairing", "err", err)
		return
	}
	s.log.Info("dispatch paired", "peer_id", Fingerprint(peer.PeerID), "addr", peer.Addr)
}

// dialLoop keeps a connection to every peer this instance is responsible for.
func (s *Service) dialLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	backoff := map[string]time.Duration{}
	next := map[string]time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			peers, err := s.store.DispatchPeers(ctx)
			if err != nil {
				s.log.Warn("dispatch cannot read pairings", "err", err)
				continue
			}
			for _, p := range peers {
				if p.Suspended || p.LastAddr == "" || !s.shouldDial(p.PeerID) {
					continue
				}
				if s.isLive(p.PeerID) {
					backoff[p.PeerID] = 0
					continue
				}
				if t, ok := next[p.PeerID]; ok && now.Before(t) {
					continue
				}
				backoff[p.PeerID] = nextBackoff(backoff[p.PeerID])
				next[p.PeerID] = now.Add(backoff[p.PeerID])

				s.wg.Add(1)
				go func(p PeerRecord) {
					defer s.wg.Done()
					s.dial(ctx, p)
				}(p)
			}
		}
	}
}

// shouldDial decides which side opens the connection.
//
// The instance with the lexicographically lower peer ID dials. A deterministic
// rule rather than both trying: two simultaneous connections between the same
// pair would each be valid, and choosing between them afterwards is a
// distributed agreement problem nobody needs to have.
func (s *Service) shouldDial(peerID string) bool {
	return s.id.PeerID() < peerID
}

// dial opens one outbound connection.
func (s *Service) dial(ctx context.Context, p PeerRecord) {
	cfg, err := ClientTLS(s.id, PinnedTo(p.PublicKey))
	if err != nil {
		s.log.Error("dispatch client config", "err", err)
		return
	}
	d := net.Dialer{Timeout: HandshakeTimeout}
	raw, err := d.DialContext(ctx, "tcp", p.LastAddr)
	if err != nil {
		s.log.Debug("dispatch dial failed", "peer", p.PeerID, "err", err)
		return
	}
	conn, err := Handshake(ctx, raw, cfg, false)
	if err != nil {
		s.log.Debug("dispatch handshake failed", "peer", p.PeerID, "err", err)
		return
	}
	s.run(ctx, conn)
}

// nextBackoff doubles a delay, bounded, with jitter.
func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next < backoffMin {
		next = backoffMin
	}
	if next > backoffMax {
		next = backoffMax
	}
	spread := float64(next) * backoffJitter
	return next + time.Duration((rand.Float64()*2-1)*spread)
}

// run serves one authenticated connection until it ends.
func (s *Service) run(ctx context.Context, conn *Conn) {
	peerID := conn.PeerID()

	if !s.register(conn) {
		conn.SayGoodbye("already connected")
		return
	}
	// At info, not debug. Somebody who turned peering on needs to see that it
	// actually worked without raising the log level, the whole point of the
	// feature is visibility, and a silent success is indistinguishable from a
	// silent failure.
	s.log.Info("dispatch peer connected",
		"peer_id", Fingerprint(peerID), "addr", conn.RemoteAddr().String())

	// The peer's address is *not* recorded here. On an inbound connection
	// RemoteAddr is the peer's ephemeral source port, and storing that would
	// overwrite a good address with one nothing can dial, which is precisely
	// the bug this replaced. The address is recorded from the peer's hello,
	// which states the port it listens on.
	defer func() {
		s.log.Info("dispatch peer disconnected", "peer_id", Fingerprint(peerID))
		s.unregister(peerID, conn)
	}()

	if err := conn.Send(TypeHello, Hello{
		PeerID: s.id.PeerID(), Clock: time.Now().Unix(), Mode: "deputy",
		ListenPort: s.listenPort(), Label: selfLabel(),
	}); err != nil {
		s.log.Debug("dispatch hello failed", "peer", peerID, "err", err)
		return
	}

	stop := make(chan struct{})
	defer close(stop)
	go s.keepAlive(conn, stop)
	go s.sendSummaries(ctx, conn, stop)

	for {
		env, err := conn.Receive()
		switch {
		case err == nil:
		case errors.Is(err, ErrUnknownType):
			// A newer peer added a message this build does not implement. Log
			// and carry on: the connection is otherwise healthy, and refusing it
			// would make every future addition a breaking change.
			s.log.Debug("dispatch ignoring unknown message",
				"peer", peerID, "type", env.Type)
			continue
		default:
			s.log.Debug("dispatch connection ended", "peer", peerID, "err", err)
			return
		}

		if err := s.handle(ctx, conn, env); err != nil {
			s.log.Warn("dispatch closing connection",
				"peer", peerID, "type", env.Type, "err", err)
			conn.SayGoodbye("protocol error")
			return
		}
		s.touch(peerID)
	}
}

// handle dispatches one message. Returning an error closes the connection.
func (s *Service) handle(ctx context.Context, conn *Conn, env Envelope) error {
	switch env.Type {
	case TypeHello:
		body, err := DecodeBody[Hello](env)
		if err != nil {
			return err
		}
		// Where to dial this peer next time. Host from the connection, port from
		// the peer, see dialAddr for why the peer may not name a host.
		if addr := dialAddr(conn.RemoteAddr(), body.ListenPort); addr != "" {
			if err := s.store.SetDispatchPeerAddr(ctx, conn.PeerID(), addr); err != nil {
				s.log.Debug("dispatch cannot record a peer address",
					"peer", conn.PeerID(), "err", err)
			}
		}
		// A name, if this peer has none yet. Not an overwrite: whatever the
		// operator typed here wins forever, because naming the far end is a
		// local preference. This is what gives a pairing made before the label
		// was exchanged something to show other than a 29-character
		// fingerprint, without anybody having to pair again.
		if body.Label != "" {
			if err := s.store.SetDispatchPeerLabelIfEmpty(ctx, conn.PeerID(), body.Label); err != nil {
				s.log.Debug("dispatch cannot record a peer name",
					"peer", conn.PeerID(), "err", err)
			}
		}
		if skew := time.Since(time.Unix(body.Clock, 0)); skew > MaxClockAhead || skew < -MaxClockAhead {
			// Surfaced rather than corrected: a wrong clock on a security tool
			// is itself worth knowing about.
			s.log.Info("dispatch peer clock differs",
				"peer", conn.PeerID(), "skew", skew.Round(time.Second))
		}
		return nil

	case TypeSummary:
		body, err := DecodeBody[SummaryMessage](env)
		if err != nil {
			return err
		}
		kept, dropped, err := body.Sanitize(time.Now())
		if err != nil {
			return err
		}
		if dropped > 0 {
			s.log.Info("dispatch dropped unusable buckets",
				"peer", conn.PeerID(), "dropped", dropped, "kept", len(kept))
		}
		// **The peer ID comes from the connection, never from the message.**
		n, err := s.store.MergeDispatchSummaries(ctx, conn.PeerID(), kept, time.Now())
		if err != nil {
			// A store error is ours, not the peer's. Log it and keep the
			// connection: dropping a healthy peer because our disk is full
			// would turn one problem into two.
			s.log.Warn("dispatch merge failed", "peer", conn.PeerID(), "err", err)
			return nil
		}
		s.log.Debug("dispatch merged summaries", "peer", conn.PeerID(), "buckets", n)
		return nil

	case TypePing:
		body, err := DecodeBody[Ping](env)
		if err != nil {
			return err
		}
		return conn.Send(TypePong, Pong{Nonce: body.Nonce, Clock: time.Now().Unix()})

	case TypePong, TypeFinding, TypeDevice:
		return nil

	case TypeBye:
		return errors.New("peer said goodbye")
	}
	return nil
}

// sendSummaries offers this instance's aggregates to a connected peer.
//
// Sent immediately on connect and then periodically: a peer that has just
// reconnected should not wait two minutes to be useful.
//
// A failure here never closes the connection. Building summaries touches the
// database, and a slow or busy disk is our problem rather than the peer's,
// dropping a healthy peer because a query timed out would turn one fault into
// two.
func (s *Service) sendSummaries(ctx context.Context, conn *Conn, stop <-chan struct{}) {
	send := func() {
		buckets, err := s.store.LocalSummaries(ctx, time.Now().Add(-summaryWindow), MaxBuckets)
		if err != nil {
			s.log.Warn("dispatch cannot build summaries", "err", err)
			return
		}
		if len(buckets) == 0 {
			return
		}
		if err := conn.Send(TypeSummary, SummaryMessage{Buckets: buckets}); err != nil {
			s.log.Debug("dispatch summary send failed", "peer", conn.PeerID(), "err", err)
			return
		}
		s.log.Debug("dispatch sent summaries",
			"peer", conn.PeerID(), "buckets", len(buckets))
	}
	send()

	t := time.NewTicker(summaryInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		}
	}
}

// keepAlive pings a quiet connection so the idle timeout means "gone" rather
// than "had nothing to say".
func (s *Service) keepAlive(conn *Conn, stop <-chan struct{}) {
	t := time.NewTicker(KeepAlive)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if err := conn.Send(TypePing, Ping{Nonce: now.UnixNano(), Clock: now.Unix()}); err != nil {
				return
			}
		}
	}
}

// register records a live connection, refusing a second one to the same peer.
func (s *Service) register(conn *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.live) >= MaxPeers {
		return false
	}
	if _, exists := s.live[conn.PeerID()]; exists {
		return false
	}
	s.live[conn.PeerID()] = conn
	s.seen[conn.PeerID()] = time.Now()
	return true
}

func (s *Service) unregister(peerID string, conn *Conn) {
	s.mu.Lock()
	if s.live[peerID] == conn {
		delete(s.live, peerID)
	}
	s.mu.Unlock()
	_ = conn.Close()
}

func (s *Service) isLive(peerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.live[peerID]
	return ok
}

func (s *Service) touch(peerID string) {
	s.mu.Lock()
	s.seen[peerID] = time.Now()
	s.mu.Unlock()
}

// States reports every paired peer's status, for the dashboard.
//
// Reads only in-memory state and the pairing list. Never waits on a peer: this
// can be called from an API handler, and a handler that could block on a network
// peer would make one unreachable laptop stall the whole dashboard.
func (s *Service) States(ctx context.Context) ([]PeerState, error) {
	peers, err := s.store.DispatchPeers(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]PeerState, 0, len(peers))
	for _, p := range peers {
		// Rendered grouped, like the instance's own id above it. An ungrouped
		// 25-character run beside a grouped one reads as a different kind of
		// thing, and both are the same kind of thing.
		// The address we would dial, not the port they happened to arrive from.
		// On the listening side the latter is an ephemeral source port, which is
		// true but useless and reads like a misconfiguration.
		// **Raw, not grouped.** An earlier version rendered this with Fingerprint
		// for display consistency, which quietly broke every join against it: the
		// destinations endpoint returns the identifier as stored, and a formatted
		// id matches nothing. Identifiers are data; grouping is presentation and
		// belongs in the view that shows them.
		st := PeerState{PeerID: p.PeerID, Label: p.Label, Addr: p.LastAddr}
		_, live := s.live[p.PeerID]
		st.Connected = live
		st.LastSeen = s.seen[p.PeerID]

		switch {
		case p.Suspended:
			st.Status = "suspended"
		case live && time.Since(st.LastSeen) < greyAfter:
			st.Status = "connected"
		default:
			st.Status = "grey"
		}
		// A peer never heard from has stale data by definition, there is none.
		st.DataStale = st.LastSeen.IsZero() || time.Since(st.LastSeen) > staleAfter
		out = append(out, st)
	}
	return out, nil
}

// StartPairing opens a pairing window and returns the code to display.
//
// Only one at a time: two open windows would mean two unpinned keys admitted
// at once, and there is no interface in which a person is pairing two machines
// in the same instant.
func (s *Service) StartPairing() (*PairingSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairing != nil && !s.pairing.expired(time.Now()) {
		return nil, errors.New("dispatch: a pairing code is already showing")
	}
	ps, err := NewPairingSession(s.id, time.Now())
	if err != nil {
		return nil, err
	}
	s.pairing = ps
	s.log.Info("dispatch pairing window open", "expires_in", PairingWindow)
	return ps, nil
}

// CancelPairing closes the window. Called when the pairing screen closes, so a
// displayed code never outlives the screen showing it.
func (s *Service) CancelPairing() {
	s.mu.Lock()
	ps := s.pairing
	s.pairing = nil
	s.mu.Unlock()
	if ps != nil {
		ps.Cancel()
		s.log.Info("dispatch pairing window closed")
	}
}

// hasPairingSession reports whether an unpinned key may currently be admitted.
func (s *Service) hasPairingSession() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pairing != nil && !s.pairing.expired(time.Now())
}

// takePairing removes and returns the open session.
func (s *Service) takePairing() *PairingSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := s.pairing
	s.pairing = nil
	return ps
}

// JoinWithCode pairs this instance with one displaying a code.
//
// **The label sent is this machine's own name, not the one being joined.**
//
// Both halves of the exchange carry the sender's name for itself: that is how
// each side ends up with something human to show for the other. The accepting
// side already sent selfLabel(); this side passed through whatever the operator
// typed into the join form, which is a name for the *remote* machine. So the
// machine displaying the code learned its new peer was called "Pi in the
// basement", or, when the field was left blank as it usually is, learned
// nothing and displayed a 29-character fingerprint as the peer's name.
//
// The typed name still does its job: it is applied to the peer here, after the
// exchange, overriding the name that peer chose for itself. Naming the far end
// is a local preference and belongs on this machine only.
func (s *Service) JoinWithCode(ctx context.Context, addr, code, label string) (PairedPeer, error) {
	peer, err := JoinWithCode(ctx, s.id, addr, code, selfLabel(), s.listenPort())
	if err != nil {
		return PairedPeer{}, err
	}
	if label = strings.TrimSpace(label); label != "" {
		peer.Label = label
	}
	if err := s.store.AddDispatchPeer(ctx, peer); err != nil {
		return PairedPeer{}, err
	}
	s.log.Info("dispatch paired", "peer_id", Fingerprint(peer.PeerID), "addr", peer.Addr)
	return peer, nil
}

// FingerprintFor renders a peer id for display.
func FingerprintFor(peerID string) string {
	if strings.Contains(peerID, "-") {
		return peerID
	}
	return Fingerprint(peerID)
}
