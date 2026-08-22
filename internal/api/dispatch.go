package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/291-Group/LAN-Sheriff/internal/dispatch"
	"github.com/291-Group/LAN-Sheriff/internal/enrich"
	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The Dispatch's read surface.
//
// One endpoint, deliberately: the dashboard needs to know whether peering is on,
// because the privacy statement it shows is only true while it is off. That is
// the whole reason this exists before any peer management UI does, a claim the
// product makes about itself must be driven by what the product is actually
// doing, not by what it was doing when the copy was written.

// DispatchState is what the dashboard is told about peering.
type DispatchState struct {
	// Enabled reports whether peering is running at all. When false, nothing
	// this instance observes has ever left the machine.
	Enabled bool `json:"enabled"`
	// PeerID identifies this instance to the people it pairs with, grouped for
	// reading aloud.
	PeerID string `json:"peer_id,omitempty"`
	// Listen is where peers reach this instance.
	Listen string `json:"listen,omitempty"`
	// Peers is every pairing and its current state.
	Peers []dispatch.PeerState `json:"peers"`
}

// handleDispatch reports peering state.
//
// Never blocks on a peer: States reads in-memory status and the pairing list, so
// an unreachable machine cannot stall this request. That property has its own
// test in the dispatch package.
// handlePeeringToggle switches peer sharing on or off without a restart.
//
// # Why this is allowed from the dashboard at all
//
// Peer sharing is the one feature that moves data off this machine, and the
// first version made it a command-line flag for that reason. In practice that
// made it the only setting in the application requiring somebody to quit, edit
// a command line and start again, on the machine most likely to be a Pi in a
// cupboard, reached over SSH, by somebody holding a phone.
//
// The security argument for keeping it out of the dashboard is weaker than it
// looks. Anyone who can reach this endpoint can already read every connection
// this instance has recorded and export the lot as CSV. Turning peering on
// grants them no new sight of anything.
//
// What it does grant is **persistence**, an export is one grab, a pairing
// keeps sending after they walk away. That is a real difference, and it is
// answered by making the state impossible to hide rather than hard to reach:
// the footer of every view says whether sharing is on and with how many
// machines, `lan-sheriff status` answers the same from a terminal with no
// password, and the pairing ledger outlives any unpairing. Enabling and
// disabling are recorded there too.
//
// Turning it *on* still shares nothing on its own. No peer exists until
// somebody carries a code between two machines.
func (s *Server) handlePeeringToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "expected {\"enabled\": true|false}")
		return
	}

	if body.Enabled {
		if s.Peering() != nil {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": true})
			return
		}
		if s.StartPeering == nil {
			writeErr(w, http.StatusConflict, "dispatch_unavailable",
				"this instance cannot start peer sharing")
			return
		}
		dsp, err := s.StartPeering(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "dispatch_unavailable", err.Error())
			return
		}
		s.SetPeering(dsp)
		s.recordPeeringChange(r.Context(), true)
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true})
		return
	}

	// Off. Existing pairings are kept: switching sharing off is not the same
	// decision as unpairing, and conflating them would silently discard peers
	// somebody spent effort establishing.
	if d := s.Peering(); d != nil {
		s.SetPeering(nil)
		d.Stop()
		s.recordPeeringChange(r.Context(), false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

// recordPeeringChange remembers the choice and writes it to the ledger.
func (s *Server) recordPeeringChange(ctx context.Context, on bool) {
	value := "off"
	if on {
		value = "on"
	}
	if err := s.Store.SetSetting(ctx, "dispatch_enabled", value); err != nil {
		slog.Warn("could not remember the peer sharing setting", "err", err)
	}
	if err := s.Store.LogPeeringChange(ctx, on); err != nil {
		slog.Warn("could not record the peer sharing change", "err", err)
	}
}

func (s *Server) handleDispatch(w http.ResponseWriter, r *http.Request) {
	state := DispatchState{Peers: []dispatch.PeerState{}}

	if s.Peering() == nil {
		// Off. Reported as a fact rather than a 404, because "peering is not
		// running" is exactly what the dashboard needs to know in order to make
		// the strong privacy claim honestly.
		writeJSON(w, http.StatusOK, state)
		return
	}

	state.Enabled = true
	state.PeerID = dispatch.Fingerprint(s.Peering().Identity().PeerID())
	if addr := s.Peering().Addr(); addr != nil {
		state.Listen = addr.String()
	}

	peers, err := s.Peering().States(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "dispatch_unavailable",
			"could not read peer state")
		return
	}
	if peers != nil {
		state.Peers = peers
	}
	writeJSON(w, http.StatusOK, state)
}

// dispatchOff writes the response for every peering endpoint when the feature
// is not running.
//
// A 409 rather than a 404: the route exists, the request was well formed, and
// the reason it cannot be served is a state the caller can do something about.
// A 404 would suggest the build lacks the feature.
func (s *Server) dispatchOff(w http.ResponseWriter) bool {
	if s.Peering() != nil {
		return false
	}
	writeErr(w, http.StatusConflict, "dispatch_off",
		"peer sharing is not running; start LAN Sheriff with --dispatch")
	return true
}

// handlePairStart opens a pairing window and returns the code to display.
func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	ps, err := s.Peering().StartPairing()
	if err != nil {
		writeErr(w, http.StatusConflict, "pairing_already_open", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code":       ps.Code(),
		"expires_at": ps.ExpiresAt().UTC(),
		// Shown beside the code so the operator knows what to type on the other
		// machine. Deliberately not encoded into the code itself: addresses
		// change, and a code carrying a stale one would be wrong the moment DHCP
		// moved.
		"listen": listenAddr(s),
	})
}

// handlePairCancel closes the window.
//
// Called when the pairing screen closes, so a displayed code never outlives the
// screen showing it. A code left live on a closed screen is a credential nobody
// is watching.
func (s *Server) handlePairCancel(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	s.Peering().CancelPairing()
	w.WriteHeader(http.StatusNoContent)
}

// handlePairJoin pairs with an instance that is displaying a code.
func (s *Server) handlePairJoin(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	var req struct {
		Addr  string `json:"addr"`
		Code  string `json:"code"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}
	if req.Addr == "" || req.Code == "" {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest,
			"both an address and a code are needed")
		return
	}

	peer, err := s.Peering().JoinWithCode(r.Context(), req.Addr, req.Code, req.Label)
	if err != nil {
		// Distinguished so the dashboard can say something useful rather than
		// "pairing failed": a mistyped code, the wrong machine and an
		// unreachable address are three different problems with three different
		// fixes.
		code, status := "pair_failed", http.StatusBadRequest
		switch {
		// **Refused is not unreachable.**
		//
		// The far side accepts an unknown key only while it is showing a code.
		// With no window open it completes the TCP connection and then drops
		// the handshake, which surfaced as "could not reach that address" and
		// sent people looking for a network fault. The address was fine; the
		// other machine simply was not offering to pair.
		case errors.Is(err, dispatch.ErrPeerDeclined), isHandshakeRefused(err):
			// Two shapes of the same situation. isHandshakeRefused catches the
			// far side dropping the TLS handshake; ErrPeerDeclined catches it
			// completing the handshake and then saying goodbye, which is what
			// it does when no pairing window is open. The second fell through
			// to the generic case and was shown as "could not reach that
			// address" over a connection that had demonstrably been reached.
			code = "pair_not_showing"
		case errors.Is(err, dispatch.ErrWrongMachine):
			code = "pair_wrong_machine"
		case errors.Is(err, dispatch.ErrBadProof):
			code = "pair_bad_code"
		case errors.Is(err, dispatch.ErrCodeLength), errors.Is(err, dispatch.ErrCodeChars):
			code = "pair_malformed_code"
		case errors.Is(err, dispatch.ErrCodeVersion):
			code = "pair_version"
		default:
			// **Refused and dropped are opposite problems.**
			//
			// Both used to arrive as "could not reach that address", which is
			// the least useful thing that could be said: refused means the
			// address is right and nothing is listening, dropped means
			// something is discarding the packets in silence, which is what a
			// host firewall does. Sending somebody to check an address that
			// was correct all along is worse than saying nothing.
			// **Before blaming a firewall, check the address is even on this
			// network.**
			//
			// Both branches below send the reader to inspect firewalls, VPNs
			// and security software. If the two machines are not on the same
			// network none of that is the problem, and telling somebody to
			// turn off protections that were never involved is worse than
			// unhelpful. The address says so on its own, for free.
			if ap, perr := netip.ParseAddrPort(req.Addr); perr == nil {
				if locals, off := dispatch.OffSubnet(ap.Addr()); off {
					nets := make([]string, 0, len(locals))
					for _, p := range locals {
						nets = append(nets, p.String())
					}
					writeErr(w, http.StatusBadRequest, "pair_off_subnet",
						fmt.Sprintf("%s is not on a network this machine is connected to (%s)",
							ap.Addr(), strings.Join(nets, ", ")))
					return
				}
			}

			switch dispatch.Classify(err) {
			case dispatch.ReachRefused:
				// A VPN can refuse as easily as it can drop.
				//
				// The VPN check used to live only under ReachDropped, on the
				// reasoning that a kill switch discards traffic silently. It
				// does not always: NordVPN on Windows produced a refusal, so
				// the one message that would have explained it was never
				// reached, and the user was told "the address is right and
				// nothing is listening" while a VPN sat in front of the route.
				// They uninstalled it to find out. That is a diagnosis the
				// software should have offered.
				switch vpn, found := dispatch.VPNPresent(); {
				case dispatch.TailscalePresent():
					code = "pair_refused_tailscale"
				case found:
					code = "pair_refused_vpn"
					err = fmt.Errorf("%w (%s appears to be running here)", err, vpn)
				default:
					code = "pair_refused"
				}
			case dispatch.ReachDropped:
				// Named only when it is actually here, and only alongside a
				// timeout, because Tailscale's Block incoming connections
				// produces exactly this and is otherwise near-undiagnosable.
				// Tailscale first: its "Block incoming connections"
				// setting is on by default for many people and is the
				// single commonest cause. Then any other VPN, because a
				// kill switch discards traffic that does not go through
				// the tunnel and a machine on the same subnet is exactly
				// that. Both look identical from here, a connection that
				// goes nowhere, and both are worth naming rather than
				// leaving somebody to blame the software.
				switch vpn, found := dispatch.VPNPresent(); {
				case dispatch.TailscalePresent():
					code = "pair_dropped_tailscale"
				case found:
					code = "pair_dropped_vpn"
					err = fmt.Errorf("%w (%s appears to be running here)", err, vpn)
				default:
					code = "pair_dropped"
				}
			}
		}
		writeErr(w, status, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id": dispatch.Fingerprint(peer.PeerID),
		"label":   peer.Label,
		"addr":    peer.Addr,
	})
}

// handlePeerTrust suspends a peer or restores it.
func (s *Server) handlePeerTrust(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	id := strings.ReplaceAll(r.PathValue("id"), "-", "")
	var req struct {
		Trust string `json:"trust"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}
	if err := s.Store.SetPeerTrust(r.Context(), id, req.Trust); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePeerRename sets the name shown for a peer on this machine.
//
// Local only: it is never sent anywhere, and the peer is not told. Naming
// somebody else's machine is a note to yourself.
func (s *Server) handlePeerRename(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	id := strings.ReplaceAll(r.PathValue("id"), "-", "")
	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, types.ErrBadRequest, "could not read the request")
		return
	}
	label := strings.TrimSpace(req.Label)
	// Bounded, because it is drawn in a fixed column beside every peer and this
	// is the one string here a person types freely.
	if len([]rune(label)) > 40 {
		label = string([]rune(label)[:40])
	}
	if err := s.Store.RenamePeer(r.Context(), id, label); err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePeerRemove unpairs, deleting everything that peer ever reported.
func (s *Server) handlePeerRemove(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	id := strings.ReplaceAll(r.PathValue("id"), "-", "")
	if err := s.Store.RemovePeer(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func listenAddr(s *Server) string {
	if a := s.Peering().Addr(); a != nil {
		return a.String()
	}
	return ""
}

// handlePeerDestinations serves what trusted peers have reported, for the
// Watchtower's layer control.
//
// **Peer destinations carry a country and no address**, by design, see
// docs/DISPATCH-PROTOCOL.md §D-5. They are therefore placed at the country's
// centroid rather than a city. That is a consequence of the privacy decision,
// not a shortcoming: the alternative was shipping addresses between machines,
// and a slightly coarser arc is a fair price.
func (s *Server) handlePeerDestinations(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	since := rangeParam(r)

	rows, err := s.Store.PeerDestinations(r.Context(), since, 500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal,
			"could not read peer destinations")
		return
	}
	for i := range rows {
		if lat, lon, ok := enrich.CountryCentroid(rows[i].Country); ok {
			rows[i].Lat, rows[i].Lon = lat, lon
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": rows})
}

// isHandshakeRefused reports a connection that was made and then dropped during
// the pairing handshake, which is what a peer with no open pairing window does.
// Matched on the error text because the reset arrives from the kernel through
// crypto/tls rather than as a typed error anything here can compare against.
func isHandshakeRefused(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "handshake") &&
		(strings.Contains(s, "connection reset") ||
			strings.Contains(s, "EOF") ||
			strings.Contains(s, "broken pipe"))
}

// The layer a view is being asked for: this machine, one peer, or everything.
//
// One parameter, spelled the same way on every endpoint that can answer for a
// peer, because the dashboard now carries a single layer control across all of
// its views rather than one hidden inside the Watchtower.
//
//	""      this machine only, and the default, so an old client or a curl
//	        without the parameter gets exactly what it always got
//	"all"   this machine and every trusted peer
//	<id>    that peer alone
const (
	layerMine = ""
	layerAll  = "all"
)

// layerParam reads it, and reports whether peer data is wanted at all.
func layerParam(r *http.Request) (layer string, wantsPeers bool) {
	l := r.URL.Query().Get("layer")
	return l, l != layerMine
}

// peerFilter turns the layer into the peer id the store should filter on:
// empty for every peer, which is what "all" means to those queries.
func peerFilter(layer string) string {
	if layer == layerAll {
		return ""
	}
	return layer
}

// handlePeerDevices lists the devices trusted peers have reported.
//
// Its own endpoint rather than more rows on /api/devices, because the two are
// not the same shape and should not pretend to be. A Roster device carries a
// hardware address, a vendor and the services it advertises; a peer sends a
// name and some counts. Folding them together would produce rows of empty
// columns, which reads as a lookup that failed rather than as detail nobody
// ever sent.
func (s *Server) handlePeerDevices(w http.ResponseWriter, r *http.Request) {
	if s.dispatchOff(w) {
		return
	}
	layer, _ := layerParam(r)
	devices, err := s.Store.PeerDevices(r.Context(), rangeParam(r), peerFilter(layer))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, types.ErrInternal,
			"could not read peer devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}
