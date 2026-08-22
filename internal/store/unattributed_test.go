package store

import (
	"context"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
)

// Patrol Mode produces flows that belong to no known device.
//
// This is the normal case, not an edge case: packet capture sees a machine's
// traffic the instant it appears, while discovery only learns which device that
// address belongs to once the machine says something identifying. Between the
// two there are flows with a NULL `device_id` and no `device_addresses` row.
//
// Deputy Mode never produced one (every flow was this host's) so six of the
// eight rules scanned that column straight into a string and crashed the moment
// Patrol Mode was switched on for the first time:
//
//	suspicion rule failed rule=plaintext
//	  err="Scan error on column index 0, name \"device_id\":
//	       converting NULL to string is unsupported"
//
// The rules already handled the *empty* case correctly, every one of them skips
// a row it cannot attribute, because a finding needs a subject. Only the SQL was
// wrong, returning NULL where the Go code assumed "".
//
// This test exists so the class cannot return: it runs every registered rule
// against a database whose flows are entirely unattributed, and requires that
// none of them error.
func TestEveryRuleSurvivesUnattributedFlows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	// Endpoints with no enrichment at all: no org, no country, no country_name.
	// first_contact coalesced through all three and could still reach NULL.
	if _, err := s.db.Exec(`
INSERT INTO endpoints (ip, first_seen, last_seen, is_internal)
VALUES ('203.0.113.10', ?, ?, 0), ('203.0.113.11', ?, ?, 0)`,
		now.Add(-48*time.Hour).Unix(), now.Unix(),
		now.Add(-48*time.Hour).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}

	// Flows with a NULL device_id and no matching device_addresses row, exactly
	// what capture produces before discovery has identified the machine.
	for i := 0; i < 40; i++ {
		ts := now.Add(-time.Duration(i) * time.Minute).Unix()
		if _, err := s.db.Exec(`
INSERT INTO flows (flow_hash, ts_start, ts_last, device_id, src_ip, src_port,
                   dst_ip, dst_port, proto, direction, established, active)
VALUES (?, ?, ?, NULL, '192.168.99.99', ?, '203.0.113.10', ?, 'tcp', 'out', 1, 0)`,
			int64(900000+i), ts, ts, 40000+i, []int{21, 23, 80, 443, 3306}[i%5]); err != nil {
			t.Fatal(err)
		}
	}

	// A DNS event with no device either, for the two rules that read lookups.
	if _, err := s.db.Exec(`
INSERT INTO dns_events (ts, device_id, qname, qtype, answers, flagged)
VALUES (?, NULL, 'kqxvbnzmrtplwd.com', 'A', '', 'malware')`, now.Unix()); err != nil {
		t.Fatal(err)
	}

	// Every rule the engine actually runs. Listed explicitly rather than
	// reflected over, so adding a rule without considering this case is a
	// deliberate act and not an oversight.
	rules := map[string]suspicion.Rule{
		"first_contact":    suspicion.FirstContact{},
		"beaconing":        suspicion.Beaconing{},
		"rare_destination": suspicion.RareDestination{},
		"dga_domain":       suspicion.DGADomain{},
		"port_scan":        suspicion.PortScan{},
		"plaintext":        suspicion.Plaintext{},
		"volume_anomaly":   suspicion.VolumeAnomaly{},
		"threat_list":      suspicion.ThreatList{},
	}

	in := suspicion.Input{
		DB: s, Now: now, Window: 2 * time.Hour, Baseline: 30 * 24 * time.Hour,
	}
	for name, rule := range rules {
		t.Run(name, func(t *testing.T) {
			obs, err := rule.Evaluate(ctx, in)
			if err != nil {
				t.Fatalf("rule failed on unattributed flows: %v", err)
			}
			// And nothing may be reported against nobody: a finding with an
			// empty subject would render as a blank row in the Wanted List.
			for _, o := range obs {
				if o.Subject == "" {
					t.Errorf("produced a finding with no subject: %+v", o)
				}
			}
		})
	}
}
