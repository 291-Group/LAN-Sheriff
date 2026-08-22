package store

import "testing"

// The merge is the part that broke in review, so it is the part with a test.
//
// Appending produced two nodes sharing one ID whenever this machine and a peer
// had both contacted the same organization, which is the common case rather
// than an edge case: households pair precisely because they use the same
// internet. A force layout keys on the node ID, so the duplicate is not
// cosmetic, and it looks like a rendering fault rather than a data one.
func TestMergeTopologyFoldsSharedOrgs(t *testing.T) {
	local := Topology{
		Nodes: []TopoNode{
			{ID: "dev:1", Kind: "device", Label: "laptop", Conns: 5, Bytes: 50},
			{ID: "org:Cloudflare", Kind: "org", Label: "Cloudflare", Country: "US", Conns: 10, Bytes: 100},
		},
		Edges: []TopoEdge{{Source: "dev:1", Target: "org:Cloudflare", Conns: 10, Bytes: 100}},
	}
	peer := Topology{
		Nodes: []TopoNode{
			{ID: "peer:p1:tv", Kind: "peer_device", Label: "tv", Conns: 7, Bytes: 70},
			// Same organization, no country: the peer's enrichment is its own.
			{ID: "org:Cloudflare", Kind: "org", Label: "Cloudflare", Conns: 3, Bytes: 30},
		},
		Edges: []TopoEdge{{Source: "peer:p1:tv", Target: "org:Cloudflare", Conns: 3, Bytes: 30}},
	}

	got := MergeTopology(local, peer)

	seen := map[string]int{}
	for _, n := range got.Nodes {
		seen[n.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("node %q appears %d times; a shared id breaks the layout", id, n)
		}
	}
	if len(got.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3 (laptop, tv, one Cloudflare)", len(got.Nodes))
	}

	var org TopoNode
	for _, n := range got.Nodes {
		if n.ID == "org:Cloudflare" {
			org = n
		}
	}
	if org.Conns != 13 || org.Bytes != 130 {
		t.Errorf("shared org = %d conns / %d bytes, want 13 / 130: both halves must count",
			org.Conns, org.Bytes)
	}
	// The local half knew the country and the peer half did not. Merging must
	// not drop what was already known.
	if org.Country != "US" {
		t.Errorf("country = %q, want US kept from the local node", org.Country)
	}

	// Both devices keep their own edge to it. Losing one would silently claim
	// the peer never contacted the organization.
	if len(got.Edges) != 2 {
		t.Errorf("edges = %d, want 2, one from each device", len(got.Edges))
	}
}

// Devices must never merge across peers, whatever they are called.
func TestMergeTopologyKeepsDevicesApart(t *testing.T) {
	a := Topology{Nodes: []TopoNode{{ID: peerNodeID("house-a", "macbook"), Kind: "peer_device", Label: "macbook", Conns: 1}}}
	b := Topology{Nodes: []TopoNode{{ID: peerNodeID("house-b", "macbook"), Kind: "peer_device", Label: "macbook", Conns: 1}}}

	got := MergeTopology(a, b)
	if len(got.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2: two households owning a laptop of the same "+
			"name do not own the same laptop", len(got.Nodes))
	}
}

func TestPeerNodeIDsAreNamespaced(t *testing.T) {
	if got := peerNodeID("p1", "tv"); got != "peer:p1:tv" {
		t.Errorf("peerNodeID = %q", got)
	}
	// A local device id must never collide with a peer one.
	if peerNodeID("p1", "tv") == "tv" {
		t.Error("peer device ids must not look like local ones")
	}
}

// A peer's node on the map used to be labelled with the internal device id it
// reports about itself, self-0123456789ab, which reads as though the machine has
// been renamed to a hash. The peer's own name is in the same row.
func TestPeerDeviceLabelPrefersTheName(t *testing.T) {
	for _, c := range []struct {
		name, peerLabel, device, want string
	}{
		{"the peer's own machine takes the peer's name",
			"hall-pi", "self-0123456789ab", "hall-pi"},
		{"an unnamed peer falls back to the identifier",
			"", "self-0123456789ab", "self-0123456789ab"},
		{"another device keeps its own identifier, never the reporter's name",
			"hall-pi", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"and so does anything that merely mentions self",
			"hall-pi", "myself-1234", "myself-1234"},
	} {
		if got := peerDeviceLabel(c.peerLabel, c.device); got != c.want {
			t.Errorf("%s: peerDeviceLabel(%q, %q) = %q, want %q",
				c.name, c.peerLabel, c.device, got, c.want)
		}
	}
}
