package pipeline

import (
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Which end of a flow is ours has to come from the direction, not from the
// shape of the address.
//
// On IPv4 the two agreed, so reading it off the address worked: our side was
// RFC 1918 and the far side was not. IPv6 has no NAT, so this machine's own
// address is globally routable and identical in form to a destination. It was
// therefore stored as an external endpoint, enriched, and counted in the status
// bar, which is why that bar read 82 destinations beside a list of 80. Because
// macOS and Windows rotate temporary addresses for privacy, the count grew for
// as long as the install lived.
func TestOurOwnAddressIsNeverADestination(t *testing.T) {
	ts := time.Unix(1700000000, 0)

	// A global IPv6 address of this machine, and one of a real destination.
	const (
		mineV6 = "2606:6d00:f3e:cb00:c88a:8092:3079:8e2a"
		themV6 = "2606:4700:4700::1111"
		mineV4 = "192.168.1.5"
		themV4 = "93.184.216.34"
	)

	for _, c := range []struct {
		name         string
		flow         types.Flow
		wantInternal map[string]bool
	}{
		{
			name: "outbound over IPv6",
			flow: types.Flow{SrcIP: mineV6, DstIP: themV6, Direction: types.DirOut, TSLast: ts},
			// The source is ours despite being globally routable.
			wantInternal: map[string]bool{mineV6: true, themV6: false},
		},
		{
			name:         "outbound over IPv4",
			flow:         types.Flow{SrcIP: mineV4, DstIP: themV4, Direction: types.DirOut, TSLast: ts},
			wantInternal: map[string]bool{mineV4: true, themV4: false},
		},
		{
			name:         "inbound over IPv6, we are the one being reached",
			flow:         types.Flow{SrcIP: themV6, DstIP: mineV6, Direction: types.DirIn, TSLast: ts},
			wantInternal: map[string]bool{mineV6: true, themV6: false},
		},
		{
			name:         "LAN to LAN is ours at both ends",
			flow:         types.Flow{SrcIP: mineV6, DstIP: themV6, Direction: types.DirInternal, TSLast: ts},
			wantInternal: map[string]bool{mineV6: true, themV6: true},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := &Engine{
				pending: map[string]types.Flow{},
				seenIPs: map[string]endpointSightingRec{},
			}
			e.record(FlowEvent{Flow: c.flow})

			for ip, want := range c.wantInternal {
				got, ok := e.seenIPs[ip]
				if !ok {
					t.Fatalf("%s was never recorded as an endpoint", ip)
				}
				if got.internal != want {
					t.Errorf("%s: internal = %v, want %v", ip, got.internal, want)
				}
			}
		})
	}
}
