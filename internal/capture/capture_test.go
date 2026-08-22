package capture

import (
	"testing"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Effective collapses several sources into what the app as a whole can see, and
// picks the one hint worth showing. Getting the hint wrong means either an empty
// banner or nagging about something already enabled.
func TestEffectivePrefersAnActionableHint(t *testing.T) {
	p := Probe{
		Active: "deputy",
		Sources: []types.Capabilities{
			{
				Mode: "deputy", Available: true, HostEgress: true,
				ProcessAttribution: true, Topology: "host",
				Hint: "descriptive", HintCode: types.HintDeputyOnly,
			},
			{
				Mode: "patrol", Available: false, Topology: "none",
				Hint: "actionable", HintCode: types.HintPatrolNotBuilt,
				EnableCmd: "make patrol",
			},
		},
	}

	eff := p.Effective()
	// The unavailable source's hint tells the user what they could turn on, so
	// it wins over the available one's description.
	if eff.HintCode != types.HintPatrolNotBuilt {
		t.Errorf("hint code = %q, want the actionable one", eff.HintCode)
	}
	if eff.EnableCmd != "make patrol" {
		t.Errorf("enable command = %q, want it carried alongside the hint", eff.EnableCmd)
	}
	if !eff.Available || !eff.ProcessAttribution {
		t.Error("capabilities should be the union across available sources")
	}
}

func TestEffectiveFallsBackToAnAvailableSourceHint(t *testing.T) {
	// With nothing to enable, the descriptive hint is better than none: the UI
	// still needs something to show when the mode pill is clicked.
	p := Probe{
		Active: "deputy",
		Sources: []types.Capabilities{
			{Mode: "deputy", Available: true, Topology: "host",
				Hint: "deputy only", HintCode: types.HintDeputyOnly},
		},
	}
	if got := p.Effective().HintCode; got != types.HintDeputyOnly {
		t.Errorf("hint code = %q, want the available source's hint as a fallback", got)
	}
}

func TestEffectiveDropsTheHintOnceNothingIsMissing(t *testing.T) {
	// Patrol running with full visibility leaves nothing to suggest, and a
	// permanent banner saying "deputy shows this machine only" would be wrong.
	p := Probe{
		Active: "patrol",
		Sources: []types.Capabilities{
			{Mode: "deputy", Available: true, Topology: "host",
				HintCode: types.HintDeputyOnly, Hint: "deputy only"},
			{Mode: "patrol", Available: true, OtherDevices: true, DNSFeed: true,
				ByteCounts: true, Topology: "lan"},
		},
	}
	eff := p.Effective()
	if eff.HintCode != "" {
		t.Errorf("hint code = %q, want none once everything is visible", eff.HintCode)
	}
	if eff.Topology != "lan" {
		t.Errorf("topology = %q, want the most capable source's", eff.Topology)
	}
}

func TestEffectiveWithNoSources(t *testing.T) {
	eff := Probe{Active: "none"}.Effective()
	if eff.Available {
		t.Error("no sources means nothing is available")
	}
	if eff.Topology != "none" {
		t.Errorf("topology = %q, want none", eff.Topology)
	}
}

func TestTopologyRanking(t *testing.T) {
	if topologyRank("lan") <= topologyRank("host") || topologyRank("host") <= topologyRank("none") {
		t.Error("topology should rank lan > host > none")
	}
	if topologyRank("nonsense") != 0 {
		t.Error("an unknown topology should rank lowest, not highest")
	}
}

// Patrol Mode running on a switched network is the case this exists for.
//
// A switch forwards a device's unicast traffic only to that device's own port,
// so capture with full privilege still shows almost nothing of other machines,
// only broadcast and multicast. Observed on a real network: SSDP and mDNS from
// six devices, and not one of their internet connections.
//
// The product must say so. Both sources report themselves available, so the
// merge previously took the *first* one's hint (Deputy's "you are only seeing
// this machine"), and then discarded it because OtherDevices and DNSFeed were
// both true, leaving `hint_code` empty and the user staring at a Roster full of
// devices with no traffic and no explanation. That silence is the failure
// docs/VANTAGE-POINTS.md was written to prevent.
func TestPatrolVantageHintSurvivesTheMerge(t *testing.T) {
	probe := Probe{
		Active: "patrol",
		Sources: []types.Capabilities{
			{
				Mode: "deputy", Available: true,
				HostEgress: true, ProcessAttribution: true, Topology: "host",
				Hint:     "Deputy Mode sees only this machine.",
				HintCode: types.HintDeputyOnly,
			},
			{
				Mode: "patrol", Available: true,
				OtherDevices: true, DNSFeed: true, ByteCounts: true,
				DeviceInventory: true, Topology: "lan",
				Hint:     "Patrol Mode is capturing. Seeing other devices also needs a vantage point.",
				HintCode: types.HintPatrolNeedsVantage,
			},
		},
	}

	eff := probe.Effective()

	if eff.HintCode != types.HintPatrolNeedsVantage {
		t.Errorf("hint_code = %q, want %q, the caveat that belongs to the most "+
			"capable source is the one worth showing",
			eff.HintCode, types.HintPatrolNeedsVantage)
	}
	if eff.Hint == "" {
		t.Error("no hint at all: capture is limited by the network and the product says nothing")
	}
	// The capabilities themselves must still merge upward.
	if !eff.OtherDevices || !eff.DNSFeed || eff.Topology != "lan" {
		t.Errorf("capabilities did not merge: %+v", eff)
	}
}

// The opposite case must still hold: when Patrol genuinely delivers everything
// and has nothing to caution about, there is nothing left to suggest and the
// Deputy-only hint is dropped rather than nagging.
func TestDeputyOnlyHintIsDroppedWhenPatrolDelivers(t *testing.T) {
	probe := Probe{
		Active: "patrol",
		Sources: []types.Capabilities{
			{
				Mode: "deputy", Available: true, HostEgress: true, Topology: "host",
				Hint: "Deputy Mode sees only this machine.", HintCode: types.HintDeputyOnly,
			},
			{
				Mode: "patrol", Available: true, OtherDevices: true, DNSFeed: true,
				Topology: "lan",
			},
		},
	}

	if eff := probe.Effective(); eff.HintCode != "" {
		t.Errorf("hint_code = %q, want it cleared: everything is visible and "+
			"there is nothing to suggest", eff.HintCode)
	}
}

// Offline must describe itself as offline, not as whatever capture would have
// reported had it been running.
//
// The flag exists so a record copied off another machine can be read without
// the reader's own network being written into it. A dashboard that announced
// "Patrol Mode is capturing" over a database nothing is adding to would be the
// same class of untruth, and it would be baked into every screenshot taken
// this way.
func TestOfflineProbeSaysSo(t *testing.T) {
	eff := Probe{Active: "offline"}.Effective()

	if eff.Mode != "offline" {
		t.Errorf("mode = %q, want offline", eff.Mode)
	}
	if eff.Available {
		t.Error("offline reports itself as available")
	}
	if eff.HintCode != types.HintOffline {
		t.Errorf("hint code = %q, want %q", eff.HintCode, types.HintOffline)
	}
	// Nothing may claim to be observable when nothing is observing.
	if eff.HostEgress || eff.OtherDevices || eff.DNSFeed || eff.ProcessAttribution {
		t.Errorf("offline advertises live capabilities: %+v", eff)
	}
	if eff.Topology != "none" {
		t.Errorf("topology = %q, want none", eff.Topology)
	}
}
