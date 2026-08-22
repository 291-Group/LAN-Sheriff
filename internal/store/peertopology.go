package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// What a peer's half of the network looks like on the other views.
//
// # Why this file exists at all
//
// Peer sharing was built for the Watchtower and stopped there. Turning on The
// Dispatch changed one view out of five, and a reader who saw another machine's
// destinations appear on the map reasonably concluded the rest of the product
// had followed. It had not: the Precinct Map, the Roster and the search were
// still reading only this machine's tables, silently, with nothing on screen
// saying so.
//
// # What a peer actually sends, and what that permits
//
// One bucket per hour, per device, per organization: device name, organization,
// country, ASN, app, protocol, port and counts. See dispatch.SummaryBucket.
// Never an address, never a hostname, never a domain.
//
// That payload decides which views can be filled and which cannot, and the
// answer is not the same for each:
//
//   - The Precinct Map draws devices in the middle and the organizations they
//     contact around the outside. A peer bucket **is** a device-to-organization
//     edge, so this view can be filled completely. It was the largest gap and
//     the one with no excuse.
//
//   - The Roster describes a device: its maker, what it appears to be, what it
//     advertises. A peer sends a name and traffic and none of the rest, so peer
//     devices can be listed with what is genuinely known and never as an
//     ordinary Roster row. They get their own section for that reason.
//
//   - Radio Chatter needs the domains a network looked up, which is exactly what
//     peer sharing promises never to transmit. No amount of work here changes
//     that, so the view says so rather than showing this machine's lookups under
//     a heading that implies otherwise.
//
// # Identity
//
// Peer device identifiers are namespaced under the peer that reported them and
// are never matched against local device IDs. Two houses can both own a laptop
// called "macbook" and they are not the same laptop; merging them would invent
// a device that exists nowhere.
// peerDeviceLabel names a peer's node on the map.
//
// A peer only ever speaks about itself, so the device it reports is its own and
// carries an internal identifier: self-0123456789ab. That was printed on the
// map as the node's name, which tells a reader nothing and looks like the
// machine has been renamed to a hash, a complaint this project has already had
// once. The peer's chosen name is right there in the same row.
//
// A device that is not the peer's own keeps its identifier, because in that
// case the peer's name would be actively wrong: it would label somebody else's
// machine with the name of the one that reported it.
func peerDeviceLabel(peerLabel, device string) string {
	if peerLabel != "" && strings.HasPrefix(device, "self-") {
		return peerLabel
	}
	return device
}

func peerNodeID(peerID, device string) string { return "peer:" + peerID + ":" + device }

// PeerDevice is one device belonging to a peer, as far as this machine can know
// it: a name, who reported it, and what it has been talking to.
//
// Deliberately not a types.Device. That type carries a hardware address, a
// vendor, and the services a device advertises, none of which a peer sends. A
// shared type would produce rows of empty columns, which reads as a lookup that
// failed rather than as detail that was never transmitted.
type PeerDevice struct {
	PeerID string `json:"peer_id"`
	Label  string `json:"label"`  // the peer's name, not the device's
	Device string `json:"device"` // the peer's own identifier for it
	ID     string `json:"id"`     // namespaced, matches the topology node

	Orgs     int64  `json:"orgs"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	LastHour int64  `json:"last_hour"`
	TopOrg   string `json:"top_org,omitempty"`
	TopApp   string `json:"top_app,omitempty"`
}

// PeerDevices lists the devices trusted peers have reported since a time.
func (s *Store) PeerDevices(ctx context.Context, since time.Time, peerID string) ([]PeerDevice, error) {
	// The trust join is repeated from PeerDestinations deliberately rather than
	// factored out: a read path that forgets it silently reintroduces data the
	// operator chose to stop believing, so it should be visible in every query
	// that touches peer_summaries.
	q := `
SELECT ps.peer_id, COALESCE(NULLIF(p.label, ''), ps.peer_id), ps.device,
       COUNT(DISTINCT ps.org), SUM(ps.flows), SUM(ps.bytes_out + ps.bytes_in),
       MAX(ps.hour)
FROM peer_summaries ps
JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ?`
	args := []any{since.Unix(), PeerTrusted}
	if peerID != "" {
		q += ` AND ps.peer_id = ?`
		args = append(args, peerID)
	}
	q += `
GROUP BY 1, 2, 3
ORDER BY 5 DESC
LIMIT 500`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading peer devices: %w", err)
	}
	defer rows.Close()

	out := make([]PeerDevice, 0, 32)
	for rows.Next() {
		var d PeerDevice
		if err := rows.Scan(&d.PeerID, &d.Label, &d.Device, &d.Orgs, &d.Flows,
			&d.Bytes, &d.LastHour); err != nil {
			return nil, err
		}
		d.ID = peerNodeID(d.PeerID, d.Device)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The busiest organization and application per device, for the row summary.
	// A second pass rather than a window function, because the supported SQLite
	// build is whatever the user's platform ships and this is 500 rows at most.
	for i := range out {
		_ = s.db.QueryRowContext(ctx, `
SELECT COALESCE(NULLIF(org,''),''), COALESCE(NULLIF(app,''),'')
FROM peer_summaries
WHERE peer_id = ? AND device = ? AND hour >= ?
ORDER BY flows DESC LIMIT 1`,
			out[i].PeerID, out[i].Device, since.Unix()).Scan(&out[i].TopOrg, &out[i].TopApp)
	}
	return out, nil
}

// PeerTopology builds the Precinct Map's graph from what peers have reported.
//
// peerID empty means every trusted peer; otherwise just that one. The shape is
// the same Topology the local graph uses, so the view merges the two by
// appending rather than by special-casing.
func (s *Store) PeerTopology(ctx context.Context, since time.Time, peerID string) (Topology, error) {
	var topo Topology

	q := `
SELECT ps.peer_id, COALESCE(NULLIF(p.label, ''), ps.peer_id), ps.device,
       COALESCE(NULLIF(ps.org, ''), ps.country), ps.country,
       SUM(ps.flows), SUM(ps.bytes_out + ps.bytes_in)
FROM peer_summaries ps
JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ?`
	args := []any{since.Unix(), PeerTrusted}
	if peerID != "" {
		q += ` AND ps.peer_id = ?`
		args = append(args, peerID)
	}
	q += `
GROUP BY 1, 2, 3, 4, 5
ORDER BY 6 DESC
LIMIT 800`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return topo, fmt.Errorf("store: reading peer topology: %w", err)
	}
	defer rows.Close()

	type orgAgg struct {
		label, country string
		conns, bytes   int64
	}
	devices := map[string]*TopoNode{}
	orgs := map[string]*orgAgg{}
	edges := map[string]*TopoEdge{}

	for rows.Next() {
		var peerID, label, device, org, country string
		var conns, bytes int64
		if err := rows.Scan(&peerID, &label, &device, &org, &country, &conns, &bytes); err != nil {
			return topo, err
		}
		if strings.TrimSpace(org) == "" {
			// Nothing to draw an edge to. A bucket with neither organization nor
			// country is not a destination, it is a gap in someone else's
			// enrichment, and inventing a node called "" would be worse.
			continue
		}
		dev := peerNodeID(peerID, device)
		if _, ok := devices[dev]; !ok {
			devices[dev] = &TopoNode{
				ID: dev,
				// Its own kind, so the map can colour and group peer devices
				// rather than passing them off as this network's own.
				Kind:  "peer_device",
				Label: peerDeviceLabel(label, device),
				Type:  label, // the reporting peer, shown in the tooltip
			}
		}
		devices[dev].Conns += conns
		devices[dev].Bytes += bytes

		if _, ok := orgs[org]; !ok {
			orgs[org] = &orgAgg{label: org, country: country}
		}
		orgs[org].conns += conns
		orgs[org].bytes += bytes

		key := dev + "\x00" + org
		if _, ok := edges[key]; !ok {
			edges[key] = &TopoEdge{Source: dev, Target: "org:" + org}
		}
		edges[key].Conns += conns
		edges[key].Bytes += bytes
	}
	if err := rows.Err(); err != nil {
		return topo, err
	}

	for _, d := range devices {
		topo.Nodes = append(topo.Nodes, *d)
	}
	for id, o := range orgs {
		topo.Nodes = append(topo.Nodes, TopoNode{
			ID: "org:" + id, Kind: "org", Label: o.label,
			Country: o.country, Conns: o.conns, Bytes: o.bytes,
		})
	}
	for _, e := range edges {
		topo.Edges = append(topo.Edges, *e)
	}
	// Stable order, so the force layout starts from the same arrangement on
	// every poll instead of reshuffling because a map iterated differently.
	sort.Slice(topo.Nodes, func(i, j int) bool { return topo.Nodes[i].ID < topo.Nodes[j].ID })
	sort.Slice(topo.Edges, func(i, j int) bool {
		if topo.Edges[i].Source != topo.Edges[j].Source {
			return topo.Edges[i].Source < topo.Edges[j].Source
		}
		return topo.Edges[i].Target < topo.Edges[j].Target
	})
	return topo, nil
}

// PeerSearch finds organizations and applications a peer has reported.
//
// Addresses and countries are absent by design: a peer sends no address, and a
// country alone is not something anybody searches for by name here.
func (s *Store) PeerSearch(ctx context.Context, term string, since time.Time, limit int) ([]SearchResult, error) {
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 10
	}
	like := "%" + term + "%"
	rows, err := s.db.QueryContext(ctx, `
SELECT 'org', ps.org, ps.org, COALESCE(NULLIF(p.label,''), ps.peer_id), SUM(ps.flows)
FROM peer_summaries ps JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ? AND ps.org <> '' AND ps.org LIKE ?
GROUP BY 2, 4
UNION ALL
SELECT 'process', ps.app, ps.app, COALESCE(NULLIF(p.label,''), ps.peer_id), SUM(ps.flows)
FROM peer_summaries ps JOIN peers p ON p.peer_id = ps.peer_id
WHERE ps.hour >= ? AND p.trust = ? AND ps.app <> '' AND ps.app LIKE ?
GROUP BY 2, 4
ORDER BY 5 DESC
LIMIT ?`,
		since.Unix(), PeerTrusted, like,
		since.Unix(), PeerTrusted, like, limit)
	if err != nil {
		return nil, fmt.Errorf("store: peer search: %w", err)
	}
	defer rows.Close()

	out := make([]SearchResult, 0, limit)
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.Kind, &r.Key, &r.Label, &r.Peer, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MergeTopology folds a peer graph into a local one.
//
// **Not an append.** Organizations are keyed by name, so an organization both
// this machine and a peer have contacted arrives twice with the same node ID.
// Two nodes sharing an ID is not a cosmetic duplicate: the force layout keys on
// it, so edges resolve to whichever copy was indexed last and the two circles
// sit on top of each other. It looks like a rendering fault and is a data one.
//
// Merging is also the honest answer. "Your laptop and your peer's television
// both talk to this company" is precisely what the Precinct Map exists to show,
// and it can only show it if the company is one circle with lines from both.
//
// Devices never merge: their identifiers are namespaced by peer, because two
// households can each own a laptop called "macbook" and they are not the same
// laptop.
func MergeTopology(local, peer Topology) Topology {
	out := Topology{Truncated: local.Truncated + peer.Truncated}

	index := map[string]int{}
	add := func(n TopoNode) {
		if i, ok := index[n.ID]; ok {
			// Counts accumulate; descriptive fields belong to whichever copy
			// had them, and the local one is preferred because it was observed
			// here rather than reported.
			out.Nodes[i].Conns += n.Conns
			out.Nodes[i].Bytes += n.Bytes
			if out.Nodes[i].Country == "" {
				out.Nodes[i].Country = n.Country
			}
			return
		}
		index[n.ID] = len(out.Nodes)
		out.Nodes = append(out.Nodes, n)
	}
	for _, n := range local.Nodes {
		add(n)
	}
	for _, n := range peer.Nodes {
		add(n)
	}

	edges := map[[2]string]int{}
	for _, e := range append(append([]TopoEdge{}, local.Edges...), peer.Edges...) {
		k := [2]string{e.Source, e.Target}
		if i, ok := edges[k]; ok {
			out.Edges[i].Conns += e.Conns
			out.Edges[i].Bytes += e.Bytes
			continue
		}
		edges[k] = len(out.Edges)
		out.Edges = append(out.Edges, e)
	}
	return out
}
