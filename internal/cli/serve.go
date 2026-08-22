package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/291-Group/LAN-Sheriff/internal/api"
	"github.com/291-Group/LAN-Sheriff/internal/auth"
	"github.com/291-Group/LAN-Sheriff/internal/capture"
	"github.com/291-Group/LAN-Sheriff/internal/capture/deputy"
	"github.com/291-Group/LAN-Sheriff/internal/capture/patrol"
	"github.com/291-Group/LAN-Sheriff/internal/config"
	"github.com/291-Group/LAN-Sheriff/internal/discover"
	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
	"github.com/291-Group/LAN-Sheriff/internal/enrich"
	"github.com/291-Group/LAN-Sheriff/internal/httpsec"
	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/notify"
	"github.com/291-Group/LAN-Sheriff/internal/pipeline"
	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
	"github.com/291-Group/LAN-Sheriff/internal/types"
	"github.com/291-Group/LAN-Sheriff/internal/web"
)

func addServeFlags(c *cobra.Command) {
	d := config.Default()
	c.Flags().String("listen", d.Listen, "address to listen on")
	c.Flags().String("data-dir", d.DataDir, "where to keep the database and datasets")
	c.Flags().Bool("open", d.OpenBrowser, "open a browser on start")
	c.Flags().Bool("locate", d.Locate, "look up this network's own position, to draw the map from")
	c.Flags().Bool("offline", d.Offline, "show an existing database without observing anything: no capture, discovery, enrichment or location lookups")
	c.Flags().Bool("city-db", d.CityDB, "fetch the city-precision location database (62 MB to download, 125 MB on disk)")
	c.Flags().Duration("poll", d.PollInterval, "how often to read the socket tables")
	c.Flags().Bool("verbose", false, "verbose logging")
	c.Flags().Bool("allow-insecure", false, "serve to the network without requiring a password (not recommended)")
	c.Flags().Bool("require-password", false, "require a password even when bound to localhost")
	// Repeatable, because a machine can legitimately be reached by more than one
	// name, and because a single comma-separated string invites somebody to pass
	// a name that contains a comma and get a silently wrong result.
	c.Flags().StringArray("trusted-host", nil,
		"accept this Host header on a loopback bind, for a proxy terminating TLS in front (repeatable)")
	c.Flags().String("interface", "", "network interface for Patrol Mode (default: chosen automatically)")
	c.Flags().Bool("promiscuous", true, "ask the interface for traffic not addressed to this machine (Patrol Mode)")
	c.Flags().Bool("sweep", true, "send one small packet per local address so devices that never talk to this machine are still found")

	// Notifications are the only thing that sends anything off this machine, so
	// every one of these is empty by default and must be set deliberately.
	c.Flags().String("notify-webhook", "", "POST findings as JSON to this URL (off by default)")
	c.Flags().String("notify-ntfy", "", "send findings to an ntfy topic URL (off by default)")
	c.Flags().String("notify-discord", "", "send findings to a Discord webhook URL (off by default)")
	c.Flags().String("notify-slack", "", "send findings to a Slack webhook URL (off by default)")
	c.Flags().Float64("notify-min-score", 0.6, "only notify about findings at or above this score")

	// The Dispatch. Off unless --dispatch is passed: it is the only feature that
	// opens a socket other machines connect to, so enabling it is deliberate.
	c.Flags().Bool("dispatch", false, "share observations with LAN Sheriff instances you have paired (off by default)")
	c.Flags().String("dispatch-listen", "", "address to accept paired peers on, e.g. 192.168.1.10:2912")
	c.Flags().Bool("dispatch-allow-public", false, "permit The Dispatch to listen on an address reachable from the internet (not recommended)")
}

func configFrom(cmd *cobra.Command) config.Config {
	c := config.Default()
	c.Listen, _ = cmd.Flags().GetString("listen")
	c.DataDir, _ = cmd.Flags().GetString("data-dir")
	c.OpenBrowser, _ = cmd.Flags().GetBool("open")
	c.Locate, _ = cmd.Flags().GetBool("locate")
	c.Offline, _ = cmd.Flags().GetBool("offline")
	c.CityDB, _ = cmd.Flags().GetBool("city-db")
	c.PollInterval, _ = cmd.Flags().GetDuration("poll")
	c.AllowInsecure, _ = cmd.Flags().GetBool("allow-insecure")
	c.RequirePassword, _ = cmd.Flags().GetBool("require-password")
	c.TrustedHosts, _ = cmd.Flags().GetStringArray("trusted-host")
	c.Interface, _ = cmd.Flags().GetString("interface")
	c.Promiscuous, _ = cmd.Flags().GetBool("promiscuous")
	c.Sweep, _ = cmd.Flags().GetBool("sweep")
	c.Dispatch, _ = cmd.Flags().GetBool("dispatch")
	c.DispatchListen, _ = cmd.Flags().GetString("dispatch-listen")
	c.DispatchAllowPublic, _ = cmd.Flags().GetBool("dispatch-allow-public")

	c.NotifyWebhook, _ = cmd.Flags().GetString("notify-webhook")
	c.NotifyNtfy, _ = cmd.Flags().GetString("notify-ntfy")
	c.NotifyDiscord, _ = cmd.Flags().GetString("notify-discord")
	c.NotifySlack, _ = cmd.Flags().GetString("notify-slack")
	c.NotifyMinScore, _ = cmd.Flags().GetFloat64("notify-min-score")
	return c
}

// rdapUnlessOffline returns a registration resolver, or nil when the instance
// is not permitted to reach the network.
//
// A function rather than an inline conditional so the offline case is impossible
// to lose in a struct literal, which is exactly how it went missing the first
// time.
func rdapUnlessOffline(cfg config.Config) *enrich.RDAP {
	if cfg.Offline {
		return nil
	}
	return enrich.NewRDAP(cfg.DatasetDir())
}

func runServe(cmd *cobra.Command) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	cfg := configFrom(cmd)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A service manager may have its own idea of when to stop.
	//
	// Signals are the whole story on Unix, where systemd and launchd both send
	// SIGTERM. The Windows service control manager does not: it delivers a
	// control request over a channel, and a service that only watches for
	// signals never hears it, gets no clean shutdown, and is eventually killed
	// with the database mid-write. WAL makes that survivable rather than
	// harmless. This is how the Windows side injects that request; on every
	// other platform serviceStop is nil and nothing changes.
	if serviceStop != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-serviceStop:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Capture sources. Deputy Mode is always constructed: if it cannot run here
	// it reports itself unavailable and says why, rather than failing.
	// Both modes are always constructed. Each reports what it can do here, and
	// the two run together when both are available: Patrol Mode sees every
	// device, Deputy Mode names the application behind this machine's own
	// connections, and neither can do the other's job.
	self := netutil.Local()
	// Held by name as well as in the slice, so the dashboard can ask it which
	// device capture actually opened.
	patrolSrc := patrol.New(patrol.Options{
		Interface:   cfg.Interface,
		Promiscuous: cfg.Promiscuous,
		DeviceID:    self.DeviceID,
	})
	sources := []capture.Source{
		deputy.New(deputy.Options{Interval: cfg.PollInterval, DeviceID: self.DeviceID}),
		patrolSrc,
	}

	probe := capture.Probe{Active: "none"}
	// **Offline reports offline, rather than what capture would have said.**
	//
	// The sources are still constructed, they are cheap and nothing starts
	// until Run, so left alone the probe would announce "Patrol Mode is
	// capturing" over a record that is not being added to. A monitor that
	// describes a state it is not in is the failure this whole flag exists to
	// avoid, and it would have been baked into every screenshot taken with it.
	if cfg.Offline {
		sources = nil
		probe.Active = "offline"
		// Describe the record, not the absence of capture. Capabilities decide
		// what the views will render, so a flat "nothing available" hid traffic
		// volumes behind "needs Patrol mode" on a database that held byte counts
		// for every flow.
		if shape, err := st.RecordShape(ctx); err == nil {
			probe.Stored = &types.Capabilities{
				Mode:               "offline",
				HostEgress:         shape.Flows,
				OtherDevices:       shape.OtherHosts,
				ProcessAttribution: shape.Processes,
				ByteCounts:         shape.Bytes,
				DNSFeed:            shape.DNS,
				DeviceInventory:    shape.Devices,
				Topology:           topologyOf(shape),
			}
		} else {
			slog.Warn("could not read what this record contains", "err", err)
		}
	}
	for _, s := range sources {
		caps := s.Capabilities()
		probe.Sources = append(probe.Sources, caps)
		if !caps.Available {
			continue
		}
		// Patrol is the more capable mode, so it names the active mode whenever
		// it is running, even though Deputy is running alongside it.
		if caps.Mode == "patrol" || probe.Active == "none" {
			probe.Active = caps.Mode
		}
	}

	datasets := enrich.NewManager(cfg.DatasetDir())
	datasets.WithCity = cfg.CityDB
	enricher := enrich.New(st, datasets, enrich.DefaultOptions())
	defer enricher.Close()

	labeller := enrich.NewLabeller(cfg.DatasetDir())

	// Register this machine before anything else runs, so that the first flow
	// already has a device to belong to and so discovery finds an existing
	// record rather than creating a rival one. The ID is derived from the local
	// hardware address, which is what the capture sources tag flows with.
	//
	// Skipped when offline: this machine is the reader, not a subject. Writing
	// it into a record copied off somewhere else adds a device that was never
	// on that network, and it is the one device whose name and address belong
	// to whoever is doing the reading.
	if !cfg.Offline {
		if _, err := st.ObserveDevice(ctx, self.Sighting()); err != nil {
			slog.Warn("could not record this host", "err", err)
		}
	}

	// Configured before anything can produce a finding, and refused loudly if a
	// URL is wrong: a mistyped webhook should be reported at startup rather than
	// failing silently for weeks.
	notifier, err := buildNotifier(cfg)
	if err != nil {
		return err
	}
	if notifier.Enabled() {
		st.OnFinding = func(rule, subject string, score float64) {
			notifier.Notify(ctx, notify.Finding{
				Rule: rule, Subject: subject, Score: score, At: time.Now(),
			})
		}
		slog.Info("notifications enabled", "targets", len(notifier.Targets),
			"min_score", cfg.NotifyMinScore)
	}

	bus := pipeline.NewBus(512)
	engine := pipeline.NewEngine(st, bus, sources)
	engine.Labeller = labeller
	// DHCP is the only capture source that reports identity rather than traffic,
	// and it goes to the same place every other sighting does.
	engine.OnSighting = func(sg types.Sighting) {
		if _, err := st.ObserveDevice(ctx, sg); err != nil && ctx.Err() == nil {
			slog.Warn("could not record a DHCP sighting", "err", err)
		}
	}

	ln, err := listen(cfg.Listen, cmd.Flags().Changed("listen"))
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	// The fallback search may have landed somewhere other than requested, and
	// the exposure decision below depends on where we actually ended up.
	cfg.Listen = ln.Addr().String()
	loopbackOnly := httpsec.IsLoopbackBind(cfg.Listen)

	authn, err := auth.New(auth.LoadHash(cfg.PasswordFile()), auth.DefaultSessionTTL)
	if err != nil {
		return fmt.Errorf("initialise authentication: %w", err)
	}
	// A password is demanded whenever the dashboard can be reached from
	// somewhere other than this machine. Bound to loopback it is already
	// private, and a password would be friction with no benefit.
	authn.SetSetupRequired(cfg.RequiresSetup(loopbackOnly))

	// Started before the API server so it can be handed over in the struct
	// literal below. That ordering is deliberate: the first version assigned it
	// afterwards and the assignment was simply forgotten, so `/api/dispatch`
	// reported peering as off while it was running, and the dashboard would
	// have gone on promising that nothing leaves this machine. A field set in a
	// literal is visible next to its neighbours; a field set fifty lines later
	// is not.
	// **The flag is one of two ways in.** Peer sharing can also be switched on
	// from the dashboard, and that choice is remembered, otherwise the only
	// setting in the whole application that needs a restart and a command line
	// would be the one people are most likely to be configuring from a Pi over
	// SSH, or from a phone.
	//
	// The flag still wins when it is passed, so a systemd unit or a container
	// that says --dispatch gets peering regardless of what the database says.
	wantPeering := cfg.Dispatch
	if !wantPeering && !cfg.Offline {
		if v, ok, _ := st.Setting(ctx, peeringKey); ok && v == "on" {
			wantPeering = true
		}
	}

	var dsp *dispatch.Service
	if wantPeering {
		var err error
		if dsp, err = startDispatch(ctx, cfg, st); err != nil {
			return err
		}
		defer func() { dsp.Stop() }()
	}

	srv := &api.Server{
		Store: st, Bus: bus, Probe: probe, Version: Version, Build: Build,
		// Reported read-only, so a wrong automatic pick can be seen rather than
		// only inferred from an empty view.
		CaptureInterfaces: func() (string, []patrol.Interface, error) {
			all, err := patrol.Interfaces()
			if err != nil {
				return "", nil, err
			}
			return patrolSrc.ActiveInterface(), all, nil
		},
		Auth:    authn,
		Exposed: !loopbackOnly,
		DataDir: cfg.DataDir,
		// **Nil under --offline, and this is the one lookup where that matters
		// most.** The flag promises "no capture, discovery, enrichment or
		// location lookups", and it was honoured everywhere except here, where
		// the resolver was constructed unconditionally.
		//
		// The other datasets are files fetched on a schedule: downloading one
		// tells the provider that somebody downloaded a file. RDAP is not that.
		// It sends **an address observed on this network** to IANA and then to a
		// regional registry, so it tells a third party which endpoint the user
		// is looking at, one click at a time. That is precisely what somebody
		// choosing offline is refusing, and the mode was doing it anyway.
		//
		// The API already answers rdap_disabled when this is nil, and the string
		// is translated in all twelve languages, so there is nothing to build:
		// the Rap Sheet simply shows no registration section.
		RDAP:     rdapUnlessOffline(cfg),
		Labeller: labeller,
		SaveHash: func(hash string) error { return auth.SaveHash(cfg.PasswordFile(), hash) },
		// So the dashboard can say plainly when observations are being dropped,
		// rather than showing an empty timeline that looks like a quiet network.
		IngestHealth: func() any { return engine.Health() },
		StartedAt:    time.Now(),
	}
	// Set adjacent to construction on purpose. An earlier version assigned this
	// fifty lines away and the assignment was simply forgotten, so /api/dispatch
	// reported peering as off while it was running, and the dashboard went on
	// promising that nothing leaves this machine.
	srv.SetPeering(dsp)

	// How the dashboard turns peering on without a restart. Offline instances
	// get nil: a record copied off another machine has nothing to share.
	if !cfg.Offline {
		srv.StartPeering = func(ctx context.Context) (*dispatch.Service, error) {
			return startDispatch(ctx, cfg, st)
		}
	}

	srv.SetRetention(cfg.Retention)
	srv.SetOrigin(api.Origin{Label: "This network", Known: false})

	mux := http.NewServeMux()
	mux.Handle("/api/", srv.RequireAuth(srv.Routes()))
	mux.Handle("/", web.Handler())

	httpSrv := &http.Server{
		Handler:           httpsec.Headers(httpsec.GuardHost(loopbackOnly, cfg.TrustedHosts, mux)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No write timeout: the live stream is a long-lived response.
	}

	// Background work. None of it may block the dashboard coming up.
	//
	// **--offline stops everything that observes, and nothing that reads.**
	// The rules still run, because findings are derived from what is already
	// stored and a Wanted List is most of the reason to open somebody else's
	// database; the pruner and rollups still run, because they only reorganise
	// what is there. What stops is capture, discovery, enrichment lookups and
	// the origin fetch, every path that would add this machine's own
	// observations to a record it did not produce.
	//
	// The case this exists for is a database copied off another machine: a Pi
	// on a mirror port, or a box being investigated. Opening it on a laptop
	// with the ordinary build merges the laptop's network into the evidence
	// within seconds, which was demonstrated the first time this was tried,
	// a demonstration database picked up the real household, hostnames and all,
	// before the first screenshot could be taken.
	go st.RunPruner(ctx, srv.RetentionRef)
	go st.RunRollups(ctx, 10*time.Minute)
	go st.RunPresence(ctx, time.Minute)
	go st.RunDeviceTyping(ctx, 30*time.Second)
	go runSuspicion(ctx, st)
	if !cfg.Offline {
		go datasets.Ensure(ctx)
		go labeller.Ensure(ctx)
		go enricher.Run(ctx)
		go runDiscovery(ctx, st, self, cfg.Sweep)
	}

	// The Dispatch, only if asked for. A failure to start it is fatal rather
	// than a warning: somebody who passed --dispatch is relying on peers being
	// reachable, and a monitor that silently is not sharing is the same class of
	// problem as one that silently is not recording.
	// The capture pipeline. Not started when offline, this is the path that
	// would write the reader's own traffic into somebody else's record, and it
	// did exactly that on the first attempt: sixty real flows in the seconds
	// before anyone noticed.
	if !cfg.Offline {
		go func() {
			if err := engine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("pipeline stopped", "err", err)
			}
		}()
	}
	// A located origin is remembered, so a restart draws the map immediately
	// instead of asking a third party where this network is all over again.
	// That is a privacy improvement before it is a convenience one: the lookup
	// discloses the public address, and doing it once per install rather than
	// once per start is a real reduction.
	if o, ok := loadOrigin(ctx, st); ok {
		srv.SetOrigin(o)
	}
	if cfg.Locate && !cfg.Offline {
		go locateOrigin(ctx, st, srv, enricher)
	}

	url := displayURL(cfg.Listen)
	printBanner(url, probe, cfg, authn, loopbackOnly)

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server stopped", "err", err)
			stop()
		}
	}()

	if cfg.OpenBrowser {
		go openBrowser(url)
	}

	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\nshutting down")

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutCtx)
}

// startDispatch brings up peer sharing.
//
// Nothing here runs unless cfg.Dispatch is set. In particular the instance's
// keypair is created on this path and nowhere else, so an install that never
// enables peering never has a private key on disk to steal.
func startDispatch(ctx context.Context, cfg config.Config, st *store.Store) (*dispatch.Service, error) {
	listen := cfg.DispatchListen
	if listen == "" {
		// Default to this machine's own LAN address rather than every interface.
		// A wildcard bind on a tool holding a record of the network is exactly
		// what the threat model refuses.
		host := netutil.Local().IP
		if host == "" {
			return nil, errors.New(
				"--dispatch needs --dispatch-listen: this machine's local address could not be determined")
		}
		listen = net.JoinHostPort(host, "2912")
	}

	svc, err := dispatch.New(dispatch.Config{
		Enabled:     true,
		Listen:      listen,
		AllowPublic: cfg.DispatchAllowPublic,
		DataDir:     cfg.DataDir,
	}, st, slog.Default())
	if err != nil {
		return nil, err
	}
	if err := svc.Start(ctx); err != nil {
		return nil, err
	}
	slog.Info("the dispatch is on",
		"peer_id", dispatch.Fingerprint(svc.Identity().PeerID()),
		"listen", svc.Addr().String())
	return svc, nil
}

// buildNotifier assembles the configured targets.
//
// Every target is off unless a URL was given. A bad URL is an error rather than
// a warning, because a notification channel somebody believes is working and is
// not is worse than one they know is absent.
func buildNotifier(cfg config.Config) (*notify.Notifier, error) {
	n := &notify.Notifier{MinScore: cfg.NotifyMinScore}

	add := func(raw string, build func(string) (notify.Target, error)) error {
		if raw == "" {
			return nil
		}
		t, err := build(raw)
		if err != nil {
			return fmt.Errorf("notification target: %w", err)
		}
		n.Targets = append(n.Targets, t)
		return nil
	}

	if err := add(cfg.NotifyWebhook, func(u string) (notify.Target, error) { return notify.NewWebhook(u) }); err != nil {
		return nil, err
	}
	if err := add(cfg.NotifyNtfy, func(u string) (notify.Target, error) { return notify.NewNtfy(u) }); err != nil {
		return nil, err
	}
	if err := add(cfg.NotifyDiscord, func(u string) (notify.Target, error) { return notify.NewDiscord(u) }); err != nil {
		return nil, err
	}
	if err := add(cfg.NotifySlack, func(u string) (notify.Target, error) { return notify.NewSlack(u) }); err != nil {
		return nil, err
	}
	return n, nil
}

// runSuspicion evaluates the rules that feed the Wanted List.
//
// Rules reason about what is normal *here*, so they are told how much history
// exists and stay silent until there is enough of it. On a fresh install that
// means the first day produces nothing, which is correct: everything is unusual
// to a database that started an hour ago.
func runSuspicion(ctx context.Context, st *store.Store) {
	engine := &suspicion.Engine{
		Rules: []suspicion.Rule{
			suspicion.FirstContact{},
			suspicion.Beaconing{},
			suspicion.RareDestination{},
			suspicion.DGADomain{},
			suspicion.PortScan{},
			suspicion.Plaintext{},
			suspicion.VolumeAnomaly{},
			suspicion.ThreatList{},
		},
		Sink: st,
		DB:   st,
	}

	// Close findings that have stopped happening, so the list stays a statement
	// about now rather than an archive.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := st.ExpireFindings(ctx, time.Now(), store.FindingTTL); err != nil && ctx.Err() == nil {
					slog.Warn("could not expire findings", "err", err)
				}
			}
		}
	}()

	engine.RunPeriodically(ctx, suspicion.DefaultInterval, func() time.Time {
		return st.BaselineAt(ctx)
	})
}

// runDiscovery populates the Roster.
//
// Separate from the capture pipeline on purpose: discovery answers "what is on
// this network", capture answers "what is it sending". Discovery needs no
// privilege, so the Roster works in Deputy Mode for every user rather than only
// where packet capture can run.
func runDiscovery(ctx context.Context, st *store.Store, self netutil.Self, sweep bool) {
	svc := &discover.Service{
		Out: func(sg types.Sighting) {
			// A sighting of this machine must land on the record the capture
			// pipeline is already tagging flows against, not a second one.
			if sg.IsSelf {
				sg.PreferredID = self.DeviceID
			}
			if _, err := st.ObserveDevice(ctx, sg); err != nil && ctx.Err() == nil {
				slog.Warn("could not record a device sighting", "source", sg.Source, "err", err)
			}
		},
		OnError: func(source string, err error) {
			// Not fatal: a machine where multicast is firewalled still gets a
			// Roster from the neighbour table.
			slog.Info("discovery source unavailable", "source", source, "err", err)
		},
	}
	svc.Sweep = sweep
	svc.Start(ctx)
	slog.Info("device discovery started", "sources", svc.Active(), "sweep", sweep)
}

// locateOrigin finds where on the map to draw arcs from. It retries, because
// the location databases are usually still downloading when this first runs.
// topologyOf reports how much of a network graph a stored record can draw.
func topologyOf(shape store.RecordShape) string {
	switch {
	case shape.OtherHosts:
		return "lan"
	case shape.Flows:
		return "host"
	default:
		return "none"
	}
}

// peeringKey remembers whether peer sharing was switched on from the dashboard.
const peeringKey = "dispatch_enabled"

// originKey holds the last located position of this network.
const originKey = "map_origin"

// loadOrigin reads a remembered origin.
//
// Offline depends on this: nothing may go and look one up, so the only origin
// available is the one the record already carries. A record without one draws
// from a neutral point and says so, which is the honest picture.
func loadOrigin(ctx context.Context, st *store.Store) (api.Origin, bool) {
	v, ok, err := st.Setting(ctx, originKey)
	if err != nil || !ok || v == "" {
		return api.Origin{}, false
	}
	var o api.Origin
	if err := json.Unmarshal([]byte(v), &o); err != nil || !o.Known {
		return api.Origin{}, false
	}
	return o, true
}

func saveOrigin(ctx context.Context, st *store.Store, o api.Origin) {
	blob, err := json.Marshal(o)
	if err != nil {
		return
	}
	if err := st.SetSetting(ctx, originKey, string(blob)); err != nil {
		slog.Debug("could not remember the map origin", "err", err)
	}
}

func locateOrigin(ctx context.Context, st *store.Store, srv *api.Server, e *enrich.Enricher) {
	for attempt := 0; attempt < 12; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		addr, ok := netutil.PublicIP(ctx)
		if ok && e.Ready() {
			if ep, ok := e.Resolve(ctx, addr.String()); ok && (ep.Lat != 0 || ep.Lon != 0) {
				label := "This network"
				if ep.City != "" {
					label = ep.City
				} else if ep.CountryName != "" {
					label = ep.CountryName
				}
				o := api.Origin{
					Lat: ep.Lat, Lon: ep.Lon, Label: label,
					Country: ep.Country, City: ep.City, Known: true,
				}
				srv.SetOrigin(o)
				saveOrigin(ctx, st, o)
				slog.Info("map origin located", "place", label, "country", ep.Country)
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	slog.Info("could not determine this network's location; drawing the map from a neutral origin")
}

func printBanner(url string, probe capture.Probe, cfg config.Config, authn *auth.Authenticator, loopbackOnly bool) {
	eff := probe.Effective()
	fmt.Fprintf(os.Stderr, "\n  \033[33m★\033[0m  LAN Sheriff %s\n", Version)
	fmt.Fprintf(os.Stderr, "     \033[2mNothing leaves town unnoticed.\033[0m\n\n")
	fmt.Fprintf(os.Stderr, "     dashboard   %s\n", url)
	fmt.Fprintf(os.Stderr, "     mode        %s\n", modeLabel(probe))
	fmt.Fprintf(os.Stderr, "     data        %s\n", cfg.DataDir)
	fmt.Fprintf(os.Stderr, "     reachable   %s\n", reachability(loopbackOnly))
	fmt.Fprintf(os.Stderr, "     password    %s\n", passwordState(authn, loopbackOnly))
	if eff.Hint != "" {
		fmt.Fprintf(os.Stderr, "\n     \033[2m%s\033[0m\n", eff.Hint)
	}
	fmt.Fprintf(os.Stderr, "\n     \033[2mAll data stays on this machine. Observing only; nothing is blocked.\033[0m\n\n")
}

// reachability says plainly who can reach this, so nobody has to guess at
// their own exposure.
func reachability(loopbackOnly bool) string {
	if loopbackOnly {
		return "this machine only"
	}
	return "anything that can reach this host on the network"
}

func passwordState(authn *auth.Authenticator, loopbackOnly bool) string {
	switch {
	case authn.NeedsSetup():
		return "not set yet, open the dashboard to create one"
	case authn.Enabled():
		return "required"
	case loopbackOnly:
		return "not set (not needed while local only)"
	default:
		return "\033[31mNOT SET, and this server is exposed to the network\033[0m"
	}
}

func modeLabel(probe capture.Probe) string {
	switch probe.Active {
	case "deputy":
		return "Deputy (this machine, with owning apps)"
	case "patrol":
		return "Patrol (whole network)"
	default:
		return "none available"
	}
}

// displayURL turns a listen address into something clickable.
func displayURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://" + listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

func openBrowser(url string) {
	// Give the listener a moment so the first request does not race the server.
	time.Sleep(400 * time.Millisecond)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		slog.Debug("could not open a browser", "err", err)
	}
}
