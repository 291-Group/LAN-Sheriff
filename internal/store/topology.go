package store

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Building the Precinct Map's graph.
//
// The hard constraint is legibility at scale. A home network with a few hundred
// endpoints, drawn one node per destination address, is a hairball that tells the
// user nothing, and a busy machine reaches thousands of addresses in an hour.
//
// So external destinations are collapsed to the organization behind them. Fifty
// addresses belonging to one CDN are one node, which is also the truthful answer
// to "who is my network talking to": the answer is a company, not an address.
// Addresses are still reachable through the Watchtower and the Rap Sheet, where
// that detail belongs.

// TopoNode is one circle on the map.
type TopoNode struct {
	ID string `json:"id"`
	// Kind is "device" for something on this network, "org" for an external
	// destination, and "gateway" for the router.
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// Type is a device type code for internal nodes; empty for external ones.
	Type string `json:"type,omitempty"`
	// Country is the ISO code for external nodes, for colouring and tooltips.
	Country string `json:"country,omitempty"`
	Conns   int64  `json:"conns"`
	Bytes   int64  `json:"bytes"`
	// Online and Trust apply to internal nodes.
	Online bool   `json:"online,omitempty"`
	Trust  string `json:"trust,omitempty"`
	// New marks an organization this network had not contacted before the
	// window, which is the whole point of watching a map rather than a list.
	New bool `json:"new,omitempty"`
}

// TopoEdge is a line between two nodes.
type TopoEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Conns  int64  `json:"conns"`
	Bytes  int64  `json:"bytes"`
}

// Topology is the whole graph.
type Topology struct {
	Nodes []TopoNode `json:"nodes"`
	Edges []TopoEdge `json:"edges"`
	// Truncated reports that quieter organizations were folded away to keep the
	// graph readable, so the UI can say so rather than appearing to lie.
	Truncated int `json:"truncated"`
}

// maxOrgNodes bounds the graph.
//
// Beyond roughly this many, a force layout stops being a diagram and becomes
// texture: nothing is individually readable and the simulation costs more than
// it communicates. The quietest organizations are dropped rather than the
// newest or the busiest, and the count of what was dropped is reported.
const maxOrgNodes = 60

// Topology derives the graph from observed flows.
func (s *Store) Topology(ctx context.Context, f Filter) (Topology, error) {
	devices, err := s.Devices(ctx)
	if err != nil {
		return Topology{}, err
	}

	// Which device each address belongs to, so a flow recorded against an
	// address still lands on the right node.
	owner, err := s.addressOwners(ctx)
	if err != nil {
		return Topology{}, err
	}

	topo := Topology{}
	nodeIndex := map[string]int{}

	gateway := ""
	for _, d := range devices {
		id := "dev:" + d.ID
		kind := "device"
		if d.DeviceType == "router" {
			kind, gateway = "gateway", id
		}
		nodeIndex[id] = len(topo.Nodes)
		topo.Nodes = append(topo.Nodes, TopoNode{
			ID:    id,
			Kind:  kind,
			Label: deviceLabel(d),
			Type:  d.DeviceType,
			// A device that is present but silent still belongs on the map.
			Online: d.Online,
			Trust:  d.Trust,
		})
	}

	edges, orgs, err := s.orgEdges(ctx, f, owner)
	if err != nil {
		return Topology{}, err
	}

	// Keep the busiest organizations; report how many were folded away.
	if len(orgs) > maxOrgNodes {
		topo.Truncated = len(orgs) - maxOrgNodes
		orgs = orgs[:maxOrgNodes]
	}
	kept := make(map[string]bool, len(orgs))
	for _, o := range orgs {
		kept[o.ID] = true
		nodeIndex[o.ID] = len(topo.Nodes)
		topo.Nodes = append(topo.Nodes, o)
	}

	for _, e := range edges {
		if !kept[e.Target] {
			continue
		}
		// A flow whose device is unknown is still real traffic. Attributing it
		// to the gateway is closer to the truth than discarding it, because
		// everything leaving this network passes through the router.
		if _, ok := nodeIndex[e.Source]; !ok {
			if gateway == "" {
				continue
			}
			e.Source = gateway
		}
		topo.Edges = append(topo.Edges, e)
	}

	if topo.Nodes == nil {
		topo.Nodes = []TopoNode{}
	}
	if topo.Edges == nil {
		topo.Edges = []TopoEdge{}
	}
	return topo, nil
}

// addressOwners maps every known address to the device holding it.
func (s *Store) addressOwners(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, device_id FROM device_addresses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var ip, id string
		if err := rows.Scan(&ip, &id); err != nil {
			return nil, err
		}
		out[ip] = id
	}
	return out, rows.Err()
}

// orgEdges aggregates outbound flows by device and destination organization,
// busiest organization first.
func (s *Store) orgEdges(ctx context.Context, f Filter, owner map[string]string) ([]TopoEdge, []TopoNode, error) {
	clauses, args := f.where("f", "e")
	// An external destination only: an internal one is a device already on the
	// map, and drawing it as an organization would double it.
	clauses = append(clauses, "COALESCE(e.is_internal, 0) = 0")
	where := strings.Join(clauses, " AND ")
	if where == "" {
		where = "1=1"
	}

	// Grouping falls back through org, then ASN, then country, so a destination
	// that enrichment has not reached yet still appears somewhere sensible
	// instead of vanishing from the map.
	rows, err := s.db.QueryContext(ctx, `
SELECT
  COALESCE(NULLIF(f.device_id, ''), '') AS device_id,
  -- A node's label sits in a list beside "Cloudflare, Inc." and "Amazon.com,
  -- Inc.", so a bare country name there reads as the name of a company. The
  -- Precinct Map showed a node called "Canada" among them.
  --
  -- An AS number is honest and specific, so it wins over a country. Where even
  -- that is missing, the country still earns its place as a *grouping*, it
  -- keeps unattributed destinations in separate nodes rather than collapsing
  -- them into one, but it is labelled so it cannot be mistaken for an operator.
  -- The country code needs no translation.
  COALESCE(NULLIF(e.org, ''),
           CASE WHEN e.asn > 0 THEN 'AS' || e.asn END,
           CASE WHEN NULLIF(e.country, '') IS NOT NULL
                THEN 'Unknown (' || e.country || ')' END,
           'Unknown') AS org,
  COALESCE(NULLIF(e.country, ''), '') AS country,
  f.src_ip,
  COUNT(*)                              AS conns,
  SUM(f.bytes_out + f.bytes_in)         AS bytes,
  MIN(e.first_seen)                     AS org_first_seen
FROM flows f
LEFT JOIN endpoints e ON e.ip = f.dst_ip
WHERE `+where+`
GROUP BY device_id, org, country, f.src_ip`, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("topology query: %w", err)
	}
	defer rows.Close()

	type agg struct {
		conns, bytes int64
		country      string
		firstSeen    int64
	}
	orgTotals := map[string]*agg{}
	edgeTotals := map[[2]string]*TopoEdge{}

	for rows.Next() {
		var (
			deviceID, org, country, srcIP string
			conns, bytes                  int64
			firstSeen                     *int64
		)
		if err := rows.Scan(&deviceID, &org, &country, &srcIP, &conns, &bytes, &firstSeen); err != nil {
			return nil, nil, err
		}

		// Prefer the device the flow was tagged with; fall back to whoever holds
		// the source address, which covers flows captured before that device was
		// identified.
		if deviceID == "" {
			deviceID = owner[srcIP]
		}
		source := ""
		if deviceID != "" {
			source = "dev:" + deviceID
		}

		orgID := "org:" + org
		a := orgTotals[orgID]
		if a == nil {
			a = &agg{country: country}
			if firstSeen != nil {
				a.firstSeen = *firstSeen
			}
			orgTotals[orgID] = a
		}
		a.conns += conns
		a.bytes += bytes
		if a.country == "" {
			a.country = country
		}
		if firstSeen != nil && (a.firstSeen == 0 || *firstSeen < a.firstSeen) {
			a.firstSeen = *firstSeen
		}

		key := [2]string{source, orgID}
		if e := edgeTotals[key]; e != nil {
			e.Conns += conns
			e.Bytes += bytes
		} else {
			edgeTotals[key] = &TopoEdge{Source: source, Target: orgID, Conns: conns, Bytes: bytes}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	nodes := make([]TopoNode, 0, len(orgTotals))
	for id, a := range orgTotals {
		nodes = append(nodes, TopoNode{
			ID:      id,
			Kind:    "org",
			Label:   id[len("org:"):],
			Country: a.country,
			Conns:   a.conns,
			Bytes:   a.bytes,
			New:     !f.Since.IsZero() && a.firstSeen >= f.Since.Unix(),
		})
	}
	// Busiest first, so truncation drops the quietest rather than an arbitrary
	// set, and so the order is stable between requests.
	sortNodesByTraffic(nodes)

	edges := make([]TopoEdge, 0, len(edgeTotals))
	for _, e := range edgeTotals {
		edges = append(edges, *e)
	}
	return edges, nodes, nil
}

func deviceLabel(d types.Device) string {
	for _, v := range []string{d.Label, d.Name, d.Hostname, d.Model, d.IP, d.MAC} {
		if v != "" {
			return v
		}
	}
	return d.ID
}

// sortNodesByTraffic orders organizations by how much traffic they account for,
// so that truncation drops the quietest and the order is stable between
// requests. Ties break on label so the map does not reshuffle on refresh.
func sortNodesByTraffic(nodes []TopoNode) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Conns != nodes[j].Conns {
			return nodes[i].Conns > nodes[j].Conns
		}
		if nodes[i].Bytes != nodes[j].Bytes {
			return nodes[i].Bytes > nodes[j].Bytes
		}
		return nodes[i].Label < nodes[j].Label
	})
}
