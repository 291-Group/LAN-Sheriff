// Package api serves the JSON API and the live WebSocket that the embedded
// dashboard runs on.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/auth"
	"github.com/291-Group/LAN-Sheriff/internal/buildinfo"
	"github.com/291-Group/LAN-Sheriff/internal/capture"
	"github.com/291-Group/LAN-Sheriff/internal/capture/patrol"
	"github.com/291-Group/LAN-Sheriff/internal/discover"
	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
	"github.com/291-Group/LAN-Sheriff/internal/enrich"
	"github.com/291-Group/LAN-Sheriff/internal/netutil"
	"github.com/291-Group/LAN-Sheriff/internal/pipeline"
	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Server holds everything the handlers need.
type Server struct {
	Store *store.Store
	Bus   *pipeline.Bus
	Probe capture.Probe

	// Version identifies the build in /api/summary.
	Version string
	// Build is the commit count, shown beside the version. Two builds of one
	// version are otherwise indistinguishable to somebody reporting a fault.
	Build string

	// CaptureInterfaces lists the devices capture could run on, and names the
	// one it is actually using. A function rather than the source itself, so
	// this package needs no capture build tag and --offline can leave it nil.
	//
	// Exists because the automatic choice was unreportable: on Windows every
	// device is named \Device\NPF_{GUID}, the startup log was the only place
	// the pick appeared, and choosing a virtual adapter with no traffic on it
	// looks exactly like a working install with a quiet network.
	CaptureInterfaces func() (active string, all []patrol.Interface, err error)

	// Auth guards the data endpoints.
	Auth *auth.Authenticator
	// SaveHash persists a newly created password hash.
	SaveHash func(hash string) error
	// Exposed reports whether the server is reachable beyond this machine.
	Exposed bool
	// DataDir is shown in settings so the user knows where their data lives.
	DataDir string
	// RDAP resolves registration detail on demand. Optional: a nil resolver
	// simply means the Rap Sheet shows no registration section.
	RDAP *enrich.RDAP
	// Labeller categorizes domains. Optional: a nil labeller means lookups are
	// shown unlabelled, which is a degradation rather than a failure.
	Labeller *enrich.Labeller

	// Peer sharing, when it is running. **Nil is the normal case** and means
	// nothing this instance observes has ever left the machine, which is what
	// lets the dashboard make its strong privacy claim honestly.
	//
	// Guarded rather than a plain field because it can now be switched on and
	// off from the dashboard, so a request may be reading it while another is
	// replacing it. Set it through SetPeering, never directly.
	dispatchMu sync.RWMutex
	dispatch   *dispatch.Service

	// StartPeering brings peer sharing up, and is supplied by whatever is
	// hosting this server, building the service needs a listen address, a
	// data directory and a logger, none of which the API layer knows about.
	//
	// Nil means this host cannot start peering at runtime, which is a real
	// case: an instance reading somebody else's database offline has nothing
	// to share and no business sharing it.
	StartPeering func(context.Context) (*dispatch.Service, error)

	// Retention is read by the settings view and written when it changes. The
	// pruner reads it through RetentionRef, so an update takes effect on the
	// next pass without a restart.
	retentionMu sync.RWMutex
	retention   store.Retention

	// The origin is located asynchronously after startup, so it is read by
	// handlers while another goroutine may still be writing it.
	originMu sync.RWMutex
	origin   Origin
	// IngestHealth reports whether observations are reaching storage. Optional;
	// when nil the endpoint reports that health is not being tracked rather
	// than claiming everything is fine.
	IngestHealth func() any
	// StartedAt is when this process began serving, for the uptime reading.
	StartedAt time.Time
}

// SetRetention updates the retention policy in place.
func (s *Server) SetRetention(r store.Retention) {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	s.retention = r
}

// RetentionRef returns the live retention policy, so the pruner always reads
// the current value rather than a copy taken at startup.
func (s *Server) RetentionRef() store.Retention {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	return s.retention
}

// SetOrigin records where the map should draw arcs from.
func (s *Server) SetOrigin(o Origin) {
	s.originMu.Lock()
	defer s.originMu.Unlock()
	s.origin = o
}

// Peering returns the running peer-sharing service, or nil when it is off.
func (s *Server) Peering() *dispatch.Service {
	s.dispatchMu.RLock()
	defer s.dispatchMu.RUnlock()
	return s.dispatch
}

// SetPeering installs, replaces or clears the peer-sharing service.
//
// Passing nil turns the dashboard's privacy claim back into the strong one, so
// this is the single place that decides whether "nothing leaves this machine"
// is currently true.
func (s *Server) SetPeering(d *dispatch.Service) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	s.dispatch = d
}

// Origin returns the current map origin.
func (s *Server) Origin() Origin {
	s.originMu.RLock()
	defer s.originMu.RUnlock()
	return s.origin
}

// Origin is this network's position on the map.
type Origin struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Label   string  `json:"label"`
	Country string  `json:"country,omitempty"`
	City    string  `json:"city,omitempty"`
	// Known is false until the origin has been located, which lets the UI draw
	// arcs from a neutral position rather than from a wrong one.
	Known bool `json:"known"`
}

// Routes returns the API mux.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/interfaces", s.handleInterfaces)
	mux.HandleFunc("GET /api/egress", s.handleEgress)
	mux.HandleFunc("GET /api/endpoints/{ip}", s.handleEndpoint)
	mux.HandleFunc("GET /api/endpoints/{ip}/registration", s.handleRegistration)
	mux.HandleFunc("GET /api/inbound", s.handleInbound)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/platform", s.handlePlatform)
	mux.HandleFunc("POST /api/devices/{id}/trust", s.handleDeviceEdit)
	mux.HandleFunc("POST /api/devices/{id}/scan", s.handleDeviceScan)
	mux.HandleFunc("GET /api/topology", s.handleTopology)
	mux.HandleFunc("GET /api/glance", s.handleGlance)
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("GET /api/wanted", s.handleWanted)
	mux.HandleFunc("POST /api/findings/{id}/status", s.handleFindingStatus)
	mux.HandleFunc("GET /api/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /api/dispatch", s.handleDispatch)
	mux.HandleFunc("POST /api/dispatch/enabled", s.handlePeeringToggle)
	mux.HandleFunc("POST /api/dispatch/pair", s.handlePairStart)
	mux.HandleFunc("DELETE /api/dispatch/pair", s.handlePairCancel)
	mux.HandleFunc("POST /api/dispatch/join", s.handlePairJoin)
	mux.HandleFunc("POST /api/dispatch/peers/{id}/trust", s.handlePeerTrust)
	mux.HandleFunc("POST /api/dispatch/peers/{id}/name", s.handlePeerRename)
	mux.HandleFunc("DELETE /api/dispatch/peers/{id}", s.handlePeerRemove)
	mux.HandleFunc("GET /api/dispatch/destinations", s.handlePeerDestinations)
	mux.HandleFunc("GET /api/dispatch/devices", s.handlePeerDevices)
	mux.HandleFunc("GET /api/timeline", s.handleTimeline)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/flows", s.handleFlows)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("POST /api/settings", s.handleSetSettings)
	mux.HandleFunc("POST /api/wipe", s.handleWipe)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	s.authRoutes(mux)
	s.dnsRoutes(mux)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("response write failed", "err", err)
	}
}

// writeErr sends a failure with both a stable code and English prose.
//
// The dashboard shows the translation of `code`; the `error` text exists for
// anyone reading the API directly, and as the UI's fallback for a code it does
// not recognize.
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"code": code, "error": msg})
}

// rangeParam parses ?range=15m|1h|24h|7d into a start time. It defaults to the
// last hour, which is the window the live map cares about.
func rangeParam(r *http.Request) time.Time {
	v := r.URL.Query().Get("range")
	if v == "" {
		return time.Now().Add(-time.Hour)
	}
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(-d)
	}
	// Durations longer than hours need help: Go's parser has no day unit.
	if strings.HasSuffix(v, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil {
			return time.Now().AddDate(0, 0, -n)
		}
	}
	return time.Now().Add(-time.Hour)
}

func intParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// SummaryResponse is the dashboard header payload.
type SummaryResponse struct {
	store.Summary
	Mode         string `json:"mode"`
	Capabilities any    `json:"capabilities"`
	Origin       Origin `json:"origin"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Host         string `json:"host"`
	Since        int64  `json:"since"`
	// Notes is English prose for API consumers; NoteCodes is what the dashboard
	// translates.
	Notes     []string `json:"notes,omitempty"`
	NoteCodes []string `json:"note_codes,omitempty"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	since := rangeParam(r)
	sum, err := s.Store.Summary(r.Context(), since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	eff := s.Probe.Effective()

	resp := SummaryResponse{
		Summary:      sum,
		Mode:         s.Probe.Active,
		Capabilities: eff,
		Origin:       s.Origin(),
		Version:      s.Version,
		Build:        s.Build,
		Host:         netutil.Local().Hostname,
		Since:        since.Unix(),
	}
	if !eff.ByteCounts {
		resp.Notes = append(resp.Notes,
			"Byte counts are unavailable in Deputy Mode: the OS socket tables report connections, not volumes. Patrol Mode measures traffic directly.")
		resp.NoteCodes = append(resp.NoteCodes, types.NoteNoByteCounts)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleEgress(w http.ResponseWriter, r *http.Request) {
	// The Watchtower asks for outbound by default; an inbound connection is not
	// egress and must not be drawn as an arc leaving this machine.
	f := filterFrom(r, types.DirOut)
	rows, err := s.Store.Egress(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if rows == nil {
		rows = []store.EgressRow{}
	}
	// How many destinations the limit cut, so the panel can say so rather than
	// presenting a capped list as the whole picture.
	omitted, err := s.Store.EgressOmitted(r.Context(), f, len(rows))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"origin":    s.Origin(),
		"endpoints": rows,
		"truncated": omitted,
	})
}

// handleInbound lists connections opened *to* this network from outside.
//
// On a home network behind NAT this list should normally be empty or very
// short. Anything on it is either a service deliberately exposed, a router
// port-forward, or a hole something opened via UPnP without being asked, and
// the last of those is worth knowing about.
func (s *Server) handleInbound(w http.ResponseWriter, r *http.Request) {
	f := filterFrom(r, types.DirIn)
	f.Direction = types.DirIn
	rows, err := s.Store.Egress(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if rows == nil {
		rows = []store.EgressRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": rows})
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	ep, err := s.Store.Endpoint(r.Context(), ip)
	if err != nil {
		writeErr(w, http.StatusNotFound, types.ErrNotFound, "no such endpoint")
		return
	}
	writeJSON(w, http.StatusOK, ep)
}

// handleRegistration answers "who registered this address block".
//
// Separate from the endpoint itself, and fetched only when a Rap Sheet is
// opened: it is a live query to a registry, so it must never be part of loading
// a view that shows hundreds of addresses at once.
func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if s.RDAP == nil {
		writeErr(w, http.StatusServiceUnavailable, types.ErrRDAPDisabled, "registration lookups are not enabled")
		return
	}
	ip := r.PathValue("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrNotAnAddress, "not an address")
		return
	}
	// Bound the wait: the user is looking at a panel, not running a report.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	reg, ok := s.RDAP.Lookup(ctx, ip)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"found": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"found": true, "registration": reg})
}

// handleHealth reports whether the pipeline is actually recording what it sees.
//
// Its own endpoint because "the dashboard is up" and "observations are being
// stored" are different questions, and a build can answer yes to the first
// while silently failing the second.
// handlePlatform reports what this binary is and where it keeps its data.
//
// Everything here is a fact about the running program rather than about its
// observations, which is why it is a separate endpoint: it never changes while
// the process lives, and the Help page is the only thing that reads it.
func (s *Server) handlePlatform(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, types.Platform{
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		Version:          s.Version,
		Build:            s.Build,
		CaptureBuilt:     patrol.Built,
		CapturePublished: patrol.CapturePublished(),
		Distributed:      buildinfo.IsDistributed(),
		DataDir:          s.DataDir,
		DBPath:           filepath.Join(s.DataDir, "sheriff.db"),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{"tracked": s.IngestHealth != nil}
	if s.IngestHealth != nil {
		resp["ingest"] = s.IngestHealth()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDevices serves the Roster.
//
// Addresses and services are folded into each device rather than left to
// separate requests: the Roster shows them inline, and a request per device
// would mean dozens of round trips to draw one table.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devices, err := s.Store.Devices(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}

	for i := range devices {
		if addrs, err := s.Store.DeviceAddresses(ctx, devices[i].ID); err == nil {
			devices[i].Addresses = addrs
		}
		if svcs, err := s.Store.DeviceServices(ctx, devices[i].ID); err == nil {
			devices[i].Services = svcs
		}
	}

	// **Never null.** Go marshals a nil slice as `null`, and the dashboard reads
	// this as an array, so a fresh install with nothing discovered yet crashed
	// the Roster with "Cannot read properties of null" and rendered a blank
	// panel: a fresh install looking broken at the one moment it must not.
	//
	// Fixed here rather than only in the client because "no devices" and "the
	// field is missing" are different claims, and an API that says the second
	// when it means the first is wrong regardless of who is reading it.
	if devices == nil {
		devices = []types.Device{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		// The Roster means something different depending on how much this build
		// can see, and the empty case especially needs explaining: an empty
		// Roster is not the same as an empty network.
		"discovery": map[string]any{
			"gateway": gatewayString(),
		},
	})
}

// handleDeviceEdit applies a user's judgement to a device: deputize, watch or
// clear, plus a label, notes and a type override.
//
// One endpoint rather than four, because these are all the same act, the user
// telling the application something it could not work out for itself, and
// because the Roster's detail panel saves them together.
func (s *Server) handleDeviceEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "no device given")
		return
	}

	// Pointers so that an omitted field is left alone while an empty one clears.
	var req struct {
		Trust      *string `json:"trust"`
		Label      *string `json:"label"`
		Notes      *string `json:"notes"`
		DeviceType *string `json:"device_type"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}

	err := s.Store.EditDevice(r.Context(), id, store.DeviceEdit{
		Trust:      req.Trust,
		Label:      req.Label,
		Notes:      req.Notes,
		DeviceType: req.DeviceType,
	})
	switch {
	case errors.Is(err, store.ErrDeviceNotFound):
		writeErr(w, http.StatusNotFound, types.ErrNotFound, "no such device")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleGlance serves the sidebar summary: what is new, what is loudest, and
// when this network is quiet.
//
// Its own endpoint rather than part of the main summary, because it is read on
// a slow cadence from every view while the summary is read constantly. Bundling
// them would run these aggregates far more often than their answers change.
func (s *Server) handleGlance(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.Glance(r.Context(), time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"glance": g,
		// Uptime belongs to the process, not the database, so it is added here.
		"started_at": s.StartedAt,
		"version":    s.Version,
	})
}

// handleDeviceScan checks which conventional ports a device answers on.
//
// A POST, and reachable only for a device the caller named, because this is the
// one thing in the product that puts deliberate connections on the network. It
// has no scheduled caller: it happens because somebody pressed a button.
func (s *Server) handleDeviceScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	devices, err := s.Store.Devices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	var target types.Device
	for _, d := range devices {
		if d.ID == id {
			target = d
			break
		}
	}
	if target.ID == "" {
		writeErr(w, http.StatusNotFound, types.ErrNotFound, "no such device")
		return
	}

	addr, err := netip.ParseAddr(target.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "this device has no usable address")
		return
	}
	// A device off this network is not ours to knock on.
	if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "only devices on this network can be checked")
		return
	}

	// Bounded regardless of what the client does: the check must not become a
	// way to hold a connection open indefinitely.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	open, err := discover.ScanPorts(ctx, addr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if err := s.Store.RecordScannedServices(ctx, id, open); err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"open":    open,
		"checked": discover.ScanPortCount(),
	})
}

// handleWanted ranks subjects by how much is open against them.
func (s *Server) handleWanted(w http.ResponseWriter, r *http.Request) {
	wanted, err := s.Store.Wanted(r.Context(), intParam(r, "limit", 50))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"wanted": wanted})
}

// handleFindings lists what the application thinks is worth a second look.
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = store.FindingOpen
	}
	if status == "all" {
		status = ""
	}
	findings, err := s.Store.Findings(r.Context(), status, intParam(r, "limit", 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

// handleFindingStatus clears or trusts a finding.
func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "not a finding id")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}

	switch err := s.Store.SetFindingStatus(r.Context(), id, req.Status); {
	case errors.Is(err, store.ErrFindingNotFound):
		writeErr(w, http.StatusNotFound, types.ErrNotFound, "no such finding")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTopology serves the Precinct Map's graph.
// handleTopology draws the Precinct Map, for this machine, one peer, or both.
//
// The peer half is appended rather than merged: a peer's device identifiers are
// namespaced under it and never matched against local ones, because two houses
// can each own a laptop called "macbook" and they are not the same laptop.
// Organizations do coincide, and are meant to: seeing that your machine and
// your peer's both talk to the same company is the point of the view.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	layer, wantsPeers := layerParam(r)

	var topo store.Topology
	if layer != layerAll && wantsPeers {
		// A single peer's layer: this machine's own graph is not part of the
		// answer, so it is not fetched.
		topo = store.Topology{}
	} else {
		var err error
		topo, err = s.Store.Topology(r.Context(), filterFrom(r, types.DirOut))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
	}

	if wantsPeers && s.Peering() != nil {
		peerTopo, err := s.Store.PeerTopology(r.Context(), rangeParam(r), peerFilter(layer))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
			return
		}
		topo = store.MergeTopology(topo, peerTopo)
	}
	writeJSON(w, http.StatusOK, topo)
}

// gatewayString names the default route so the Roster can mark it, returning
// empty where it could not be determined.
func gatewayString() string {
	if gw := discover.DefaultGateway(); gw.IsValid() {
		return gw.String()
	}
	return ""
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"active":    s.Probe.Active,
		"sources":   s.Probe.Sources,
		"effective": s.Probe.Effective(),
	})
}

// handleInterfaces reports the capture devices and which one is in use.
//
// Read-only on purpose. Knowing what was chosen, and what else was available,
// is the whole diagnostic; changing it means tearing down and reopening a live
// capture handle, which is a separate decision with its own failure modes.
func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	type iface struct {
		patrol.Interface
		Active bool `json:"active"`
	}
	out := struct {
		Available  bool    `json:"available"`
		Active     string  `json:"active,omitempty"`
		Reason     string  `json:"reason,omitempty"`
		Interfaces []iface `json:"interfaces"`
	}{Interfaces: []iface{}}

	if s.CaptureInterfaces == nil {
		out.Reason = "capture is not running"
		writeJSON(w, http.StatusOK, out)
		return
	}
	active, all, err := s.CaptureInterfaces()
	if err != nil {
		out.Reason = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Available, out.Active = true, active
	for _, i := range all {
		out.Interfaces = append(out.Interfaces, iface{Interface: i, Active: i.Name == active})
	}
	writeJSON(w, http.StatusOK, out)
}
