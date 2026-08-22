package suspicion

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// PortScan notices a device probing many ports on one host, or one port across
// many hosts.
//
// Two shapes, both worth knowing about:
//
//   - **Vertical**: one destination, many ports. Somebody asking what a
//     particular machine runs.
//   - **Horizontal**: one port, many destinations. Somebody asking which
//     machines run a particular thing, how a worm spreads.
//
// **What separates a scan from ordinary software is that a scan is mostly
// refused.** A backup client, an FTP client, a stream deck, all touch a
// surprising number of ports, and all of them *connect*. A scan is a series of
// questions where most answers are "nothing here". Without that test the rule
// reports FileZilla.
//
// It also has to exclude this application. LAN Sheriff's own on-demand port
// check probes thirty-five ports on one host, which is precisely the vertical
// shape above, on the development machine it appears as 85 flows to a single
// destination across 85 ports. A monitor that reports itself is not a monitor.
type PortScan struct{}

func (PortScan) Code() string { return "port_scan" }

// Weight is high: unlike a new destination or an unusual country, there is no
// innocent version of a device systematically probing its neighbours.
func (PortScan) Weight() float64 { return 0.9 }

const (
	// scanLookback is the window a sweep must fit inside to count as one act.
	scanLookback = 30 * time.Minute

	// minScanPorts and minScanHosts are set above what legitimate multi-port
	// software does. An FTP client touching 26 ports and a stream deck touching
	// 11 were both visible on the development network; twenty-five with most
	// refused is a different thing.
	minScanPorts = 25
	minScanHosts = 25

	// maxEstablishedRatio is how much of a burst may have connected and still
	// count as a scan. Software that works connects; a scan mostly does not.
	maxEstablishedRatio = 0.3

	// selfProcess is this application. Its own port check is deliberately the
	// shape this rule detects.
	selfProcess = "lan-sheriff"
)

func (r PortScan) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	if in.Baseline < MinBaseline {
		return nil, nil
	}
	since := in.Now.Add(-scanLookback).Unix()

	var out []Observation

	// Vertical: one device, one destination, many ports, mostly refused.
	vertical, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
       f.dst_ip,
       COUNT(DISTINCT f.dst_port) AS ports,
       SUM(f.established) AS connected,
       MAX(f.ts_last) AS last_seen
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
WHERE f.ts_start >= ?
  AND COALESCE(f.process, '') != ?
GROUP BY 1, 2
HAVING ports >= ? AND CAST(connected AS REAL) / ports <= ?`,
		since, selfProcess, minScanPorts, maxEstablishedRatio)
	if err != nil {
		return nil, fmt.Errorf("vertical scan query: %w", err)
	}
	for vertical.Next() {
		var (
			deviceID, dst    string
			ports, connected int
			lastSeen         int64
		)
		if err := vertical.Scan(&deviceID, &dst, &ports, &connected, &lastSeen); err != nil {
			vertical.Close()
			return nil, err
		}
		if deviceID == "" {
			continue
		}
		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       scanScore(ports, minScanPorts),
			At:          time.Unix(lastSeen, 0),
			Detail: map[string]any{
				"shape":     "vertical",
				"target":    dst,
				"ports":     ports,
				"connected": connected,
			},
			Dedup: "port_scan:v:" + deviceID + ":" + dst,
		})
	}
	if err := vertical.Err(); err != nil {
		vertical.Close()
		return nil, err
	}
	vertical.Close()

	// Horizontal: one device, one port, many destinations, mostly refused.
	horizontal, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
       f.dst_port,
       COUNT(DISTINCT f.dst_ip) AS hosts,
       SUM(f.established) AS connected,
       MAX(f.ts_last) AS last_seen
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
WHERE f.ts_start >= ?
  AND COALESCE(f.process, '') != ?
GROUP BY 1, 2
HAVING hosts >= ? AND CAST(connected AS REAL) / hosts <= ?`,
		since, selfProcess, minScanHosts, maxEstablishedRatio)
	if err != nil {
		return nil, fmt.Errorf("horizontal scan query: %w", err)
	}
	defer horizontal.Close()

	for horizontal.Next() {
		var (
			deviceID         string
			port             int
			hosts, connected int
			lastSeen         int64
		)
		if err := horizontal.Scan(&deviceID, &port, &hosts, &connected, &lastSeen); err != nil {
			return nil, err
		}
		if deviceID == "" {
			continue
		}
		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       scanScore(hosts, minScanHosts),
			At:          time.Unix(lastSeen, 0),
			Detail: map[string]any{
				"shape":     "horizontal",
				"port":      port,
				"hosts":     hosts,
				"connected": connected,
			},
			Dedup: "port_scan:h:" + deviceID + ":" + strconv.Itoa(port),
		})
	}
	return out, horizontal.Err()
}

// scanScore rates a sweep by how far past the threshold it went.
func scanScore(count, threshold int) float64 {
	over := float64(count-threshold) / float64(threshold*3)
	if over > 1 {
		over = 1
	}
	return Clamp(0.7 + 0.3*over)
}
