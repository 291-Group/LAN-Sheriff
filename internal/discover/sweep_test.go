package discover

import (
	"net/netip"
	"testing"
)

func TestHostsInBoundsTheSweep(t *testing.T) {
	cases := []struct {
		prefix string
		want   int
		why    string
	}{
		{"192.168.1.0/24", 254, "the common home network"},
		{"192.168.68.0/22", 1022, "a larger but still reasonable home network"},
		{"192.168.0.0/21", 0, "2,046 hosts is past the budget"},
		{"10.0.0.0/30", 2, "a point-to-point pair"},
		{"10.0.0.0/31", 0, "no host addresses to sweep"},
		{"10.0.0.1/32", 0, "a single address is not a subnet"},
		{"10.0.0.0/16", 0, "65,534 packets is not gentle at any rate"},
		{"10.0.0.0/8", 0, "certainly not"},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		if got := hostsIn(p); got != c.want {
			t.Errorf("hostsIn(%s) = %d, want %d (%s)", c.prefix, got, c.want, c.why)
		}
	}
}

// The network and broadcast addresses belong to nobody and must never be probed.
func TestIterateHostsExcludesNetworkAndBroadcast(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	hosts := iterateHosts(p)

	if len(hosts) != 254 {
		t.Fatalf("got %d hosts, want 254", len(hosts))
	}
	for _, excluded := range []string{"192.168.1.0", "192.168.1.255"} {
		if _, ok := hosts[netip.MustParseAddr(excluded)]; ok {
			t.Errorf("%s should not be probed", excluded)
		}
	}
	for _, included := range []string{"192.168.1.1", "192.168.1.254"} {
		if _, ok := hosts[netip.MustParseAddr(included)]; !ok {
			t.Errorf("%s should be probed", included)
		}
	}
}

// A subnet too large to sweep gently is skipped entirely rather than sampled.
// Half a sweep is not half an answer, it is an answer nobody can rely on.
func TestOversizedSubnetsAreSkippedNotSampled(t *testing.T) {
	for _, s := range []string{"10.0.0.0/16", "172.16.0.0/12"} {
		p := netip.MustParsePrefix(s)
		if got := len(iterateHosts(p)); got != 0 {
			t.Errorf("%s yielded %d targets, want none", s, got)
		}
	}
}

// Whatever the local network looks like, a pass must stay within the bound.
func TestSweepStaysWithinItsBudget(t *testing.T) {
	targets, err := SweepTargets()
	if err != nil {
		t.Fatal(err)
	}
	// One pass may cover several interfaces, but each subnet is individually
	// bounded, so no single prefix can blow the budget.
	if len(targets) > maxSweepHosts*4 {
		t.Errorf("sweep would send %d packets, which is not gentle", len(targets))
	}
	seen := map[netip.Addr]bool{}
	for _, a := range targets {
		if seen[a] {
			t.Errorf("%v would be probed twice in one pass", a)
		}
		seen[a] = true
		if !a.Is4() {
			t.Errorf("%v is not IPv4; the sweep is v4-only by design", a)
		}
	}
}
