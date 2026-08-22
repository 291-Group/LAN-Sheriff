// Package capture defines the pluggable capture-source interface that every
// observation enters the pipeline through, plus the startup probe that decides
// which sources can actually run here.
package capture

import (
	"context"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Source produces raw observations. Implementations must never block the
// caller: Start returns as soon as capture is running, and everything after
// that arrives on the out channel.
//
// A Source that cannot run (no privilege, unsupported OS) is not an error. It
// reports Available=false from Capabilities and explains itself via Hint, and
// the app carries on with whatever else it has. Capture privilege must never
// hard-fail the application.
type Source interface {
	Name() string
	Capabilities() types.Capabilities
	Start(ctx context.Context, out chan<- types.RawEvent) error
	Stop() error
}

// Probe is the result of asking every known source what it can do here.
type Probe struct {
	Sources []types.Capabilities `json:"sources"`
	// Active is the mode actually running: "deputy", "patrol", "offline" or
	// "none".
	Active string `json:"active"`

	// Stored describes what a record contains when nothing is capturing, so a
	// database being read offline still renders the views its data supports.
	Stored *types.Capabilities `json:"stored,omitempty"`
}

// Effective collapses the probe into what the application as a whole can
// observe, which is the union over the sources that are actually available.
func (p Probe) Effective() types.Capabilities {
	eff := types.Capabilities{Mode: p.Active, Topology: "none"}

	// Offline has no sources by construction, and its hint is not a suggestion
	// of something to turn on, it is a statement that this record is being
	// read rather than written.
	//
	// What it *can* show comes from the record itself, in Stored. Available
	// stays false throughout: nothing is running, and a view that needs live
	// capture should still say so.
	if p.Active == "offline" {
		if p.Stored != nil {
			st := *p.Stored
			eff.HostEgress, eff.OtherDevices = st.HostEgress, st.OtherDevices
			eff.ProcessAttribution, eff.ByteCounts = st.ProcessAttribution, st.ByteCounts
			eff.DNSFeed, eff.DeviceInventory = st.DNSFeed, st.DeviceInventory
			eff.Topology = st.Topology
		}
		eff.Hint = "Nothing is being captured. This is a stored record, so it will not change while you read it."
		eff.HintCode = types.HintOffline
		return eff
	}

	// Choose the most useful hint across the sources, preferring one that names
	// something the user could turn on. An unavailable source's hint is
	// actionable ("this is how you get more"); an available one's is merely
	// descriptive, and is kept only as a fallback.
	var fallbackHint, fallbackCode, fallbackCmd, fallbackTopology string
	for _, c := range p.Sources {
		if !c.Available {
			if eff.HintCode == "" && (c.HintCode != "" || c.Hint != "") {
				eff.Hint, eff.HintCode, eff.EnableCmd = c.Hint, c.HintCode, c.EnableCmd
			}
			continue
		}
		// Among sources that *are* working, the caveat worth showing belongs to
		// the most capable one. Taking the first source's hint meant Deputy's
		// "you are only seeing this machine" won over Patrol's "capture is
		// running, but a switch will still hide other devices unless you have a
		// vantage point", and the second is the one a user needs.
		if c.HintCode != "" || c.Hint != "" {
			if fallbackCode == "" || topologyRank(c.Topology) > topologyRank(fallbackTopology) {
				fallbackHint, fallbackCode, fallbackCmd = c.Hint, c.HintCode, c.EnableCmd
				fallbackTopology = c.Topology
			}
		}
		eff.Available = true
		eff.HostEgress = eff.HostEgress || c.HostEgress
		eff.OtherDevices = eff.OtherDevices || c.OtherDevices
		eff.ProcessAttribution = eff.ProcessAttribution || c.ProcessAttribution
		eff.ByteCounts = eff.ByteCounts || c.ByteCounts
		eff.DNSFeed = eff.DNSFeed || c.DNSFeed
		eff.DeviceInventory = eff.DeviceInventory || c.DeviceInventory
		if topologyRank(c.Topology) > topologyRank(eff.Topology) {
			eff.Topology = c.Topology
		}
	}

	if eff.HintCode == "" && eff.Hint == "" {
		eff.Hint, eff.HintCode, eff.EnableCmd = fallbackHint, fallbackCode, fallbackCmd
	}
	// Once every device is visible there is nothing left to suggest, so an
	// otherwise-descriptive hint is dropped rather than nagging.
	//
	// **Only the Deputy-only hint.** `OtherDevices` means "this source is able to
	// report other devices", not "you will actually see them", on a switched
	// network Patrol Mode reports the capability and then shows almost nothing,
	// because a switch forwards a device's unicast traffic only to its own port.
	// Clearing Patrol's vantage-point hint on the strength of that flag left the
	// product silent about the one thing the user most needed to know: capture
	// is working, and the network is the reason it looks empty. That silence is
	// precisely the failure docs/VANTAGE-POINTS.md exists to prevent.
	if eff.OtherDevices && eff.DNSFeed && eff.HintCode == types.HintDeputyOnly {
		eff.Hint, eff.HintCode, eff.EnableCmd = "", "", ""
	}
	return eff
}

func topologyRank(t string) int {
	switch t {
	case "lan":
		return 2
	case "host":
		return 1
	default:
		return 0
	}
}
