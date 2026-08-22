package suspicion

import (
	"context"
	"fmt"
	"time"
)

// Plaintext notices a device sending credentials or mail over the internet
// without encryption.
//
// **Port 80 is deliberately not in this list**, which is the whole design
// decision. Ordinary browsing produces plain HTTP constantly, certificate
// status checks, redirects to HTTPS, captive-portal probes, ad networks, and a
// rule that flagged it would fire hundreds of times a day on a healthy network.
// It would also be nearly useless advice, since the user cannot do anything
// about somebody else's redirect.
//
// What is left is the short list where plaintext genuinely means credentials or
// private mail crossing the internet in the clear, and where the answer is
// actionable: stop using that service, or configure it for TLS.
type Plaintext struct{}

func (Plaintext) Code() string { return "plaintext" }

// Weight is moderate. It is a real exposure, but it is a configuration problem
// rather than evidence of an intruder.
func (Plaintext) Weight() float64 { return 0.45 }

// plaintextPorts are protocols whose unencrypted form carries credentials or
// message contents.
//
// Each has an encrypted counterpart in normal use, so seeing the plain version
// leaving the network is a genuine finding rather than an inevitability.
var plaintextPorts = map[int]string{
	21:   "FTP",
	23:   "Telnet",
	110:  "POP3",
	143:  "IMAP",
	389:  "LDAP",
	1433: "SQL Server",
	3306: "MySQL",
	5432: "PostgreSQL",
	5900: "VNC",
}

func (r Plaintext) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	since := in.Now.Add(-in.Window).Unix()

	rows, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
       f.dst_port, f.dst_ip,
       COALESCE(NULLIF(e.org, ''), f.dst_ip) AS org,
       COUNT(*) AS hits,
       MAX(f.ts_last) AS last_seen
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
LEFT JOIN endpoints e ON e.ip = f.dst_ip
WHERE f.ts_last >= ?
  AND f.established = 1
  AND f.proto = 'tcp'
  AND COALESCE(e.is_internal, 0) = 0
GROUP BY 1, 2, 3`, since)
	if err != nil {
		return nil, fmt.Errorf("plaintext query: %w", err)
	}
	defer rows.Close()

	// One finding per device and protocol: three FTP servers is one problem.
	byKey := map[string]*Observation{}

	for rows.Next() {
		var (
			deviceID, dst, org string
			port, hits         int
			lastSeen           int64
		)
		if err := rows.Scan(&deviceID, &port, &dst, &org, &hits, &lastSeen); err != nil {
			return nil, err
		}
		proto, listed := plaintextPorts[port]
		if !listed || deviceID == "" {
			continue
		}
		// Only traffic actually leaving this network. A database on the local
		// segment speaking its own protocol is normal and not this rule's
		// business.
		if !IsReportable(dst) {
			continue
		}

		dedup := "plaintext:" + deviceID + ":" + proto
		if existing, ok := byKey[dedup]; ok {
			existing.Detail["hits"] = existing.Detail["hits"].(int) + hits
			if at := time.Unix(lastSeen, 0); at.After(existing.At) {
				existing.At = at
			}
			continue
		}
		byKey[dedup] = &Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       plaintextScore(port),
			At:          time.Unix(lastSeen, 0),
			Detail: map[string]any{
				"protocol": proto,
				"port":     port,
				"org":      org,
				"hits":     hits,
			},
			Dedup: dedup,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Observation, 0, len(byKey))
	for _, o := range byKey {
		out = append(out, *o)
	}
	return out, nil
}

// plaintextScore ranks the protocols by what is actually at stake.
//
// Telnet sends a password as typed and has no legitimate modern use across the
// internet. A database protocol exposes everything it holds. FTP and mail sit
// between: bad, but often somebody else's legacy service.
func plaintextScore(port int) float64 {
	switch port {
	case 23: // Telnet
		return 0.95
	case 1433, 3306, 5432: // databases across the internet
		return 0.9
	case 5900: // VNC
		return 0.85
	case 21: // FTP
		return 0.7
	case 110, 143, 389: // mail and directory
		return 0.6
	}
	return 0.5
}
