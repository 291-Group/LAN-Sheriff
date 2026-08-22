package api

import (
	"net/http"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/store"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Radio Chatter's endpoints.
//
// The feed, its aggregates, and its own summary are separate requests rather
// than one payload, because the feed refreshes constantly while the aggregates
// change slowly. Bundling them would mean recomputing the expensive part every
// couple of seconds.

func (s *Server) dnsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns", s.handleDNS)
	mux.HandleFunc("GET /api/dns/summary", s.handleDNSSummary)
	mux.HandleFunc("GET /api/dns/domains", s.handleTopDomains)
	mux.HandleFunc("GET /api/dns/new", s.handleNewDomains)
}

func (s *Server) dnsOptions(r *http.Request) store.DNSOptions {
	since, until := timeRange(r)
	q := r.URL.Query()
	return store.DNSOptions{
		Since:       since,
		Until:       until,
		Device:      q.Get("device"),
		Domain:      q.Get("domain"),
		FlaggedOnly: q.Get("flagged") == "1",
		Limit:       intParam(r, "limit", 200),
	}
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	events, err := s.Store.DNSEvents(r.Context(), s.dnsOptions(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if events == nil {
		events = []types.DNSEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		// The UI needs to distinguish "no lookups yet" from "this mode cannot
		// see DNS at all", and only the capability probe knows which.
		"capable": s.Probe.Effective().DNSFeed,
	})
}

func (s *Server) handleDNSSummary(w http.ResponseWriter, r *http.Request) {
	since, until := timeRange(r)
	stats, err := s.Store.DNSSummary(r.Context(), since, until)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	eff := s.Probe.Effective()

	resp := map[string]any{"stats": stats, "capable": eff.DNSFeed}
	if !eff.DNSFeed {
		// Say why the feed is empty rather than leaving the user to conclude
		// their network is silent. The code is what the dashboard translates.
		resp["hint"] = "DNS lookups are only visible in Patrol Mode, or when this machine is itself the network's resolver."
		resp["hint_code"] = types.HintDNSNeedsPatrol
	}
	if s.Labeller != nil {
		resp["labelled_domains"] = s.Labeller.Size()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	since, until := timeRange(r)
	domains, err := s.Store.TopDomains(r.Context(), since, until, intParam(r, "limit", 25))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if domains == nil {
		domains = []store.DomainSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

// handleNewDomains lists names this network has never resolved before.
//
// Its own endpoint because it answers a different question from "what is busiest":
// a domain queried once, an hour ago, for the first time ever, is far more
// interesting than the thousand lookups of a CDN the network uses daily.
func (s *Server) handleNewDomains(w http.ResponseWriter, r *http.Request) {
	since, until := timeRange(r)
	if until.IsZero() {
		until = time.Now()
	}
	domains, err := s.Store.NewDomains(r.Context(), since, until, intParam(r, "limit", 50))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	if domains == nil {
		domains = []store.DomainSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
}
