package suspicion

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// VolumeAnomaly notices a device doing far more than it usually does.
//
// The measure is the device's own history, never a fixed threshold. A media
// server and a doorbell have nothing in common except that a tenfold change in
// either is worth a glance.
//
// **Counted in connections, not bytes.** Deputy Mode reads socket tables, which
// carry no byte counters, so a bytes-based rule would be silent on most installs
// , the same reason the "busiest device" widget counts connections.
//
// Two things keep it from firing on ordinary life:
//
//   - **Robust statistics.** Median and median absolute deviation, not mean and
//     standard deviation. A device's traffic is spiky by nature, and a single
//     large hour in the history would inflate a mean-based threshold enough to
//     hide everything afterwards.
//   - **Enough history to know the rhythm.** A laptop is quiet at four in the
//     morning and busy at nine. Comparing one hour against a baseline that has
//     not yet seen a full daily cycle would report every morning as an anomaly.
type VolumeAnomaly struct{}

func (VolumeAnomaly) Code() string { return "volume_anomaly" }

// Weight is moderate. A busy hour is often a large download, and the finding is
// most useful in combination with something else about the same device.
func (VolumeAnomaly) Weight() float64 { return 0.4 }

const (
	// volumeBaseline is how much history is needed before the rule speaks.
	//
	// Three days rather than one: a single day gives one sample of each hour, so
	// the daily rhythm is indistinguishable from an anomaly. Three gives the
	// spread something to be a spread of.
	volumeBaseline = 72 * time.Hour

	// volumeHistory is how far back the baseline is computed from.
	volumeHistory = 14 * 24 * time.Hour

	// minVolumeHours is how many hours of observation a device needs before its
	// own normal means anything.
	minVolumeHours = 48

	// volumeMultiple is how many times the typical deviation above the median an
	// hour must reach. Six is deliberately far out: this rule exists to catch a
	// device behaving unlike itself, not a busy evening.
	volumeMultiple = 6.0

	// minVolumeCount stops a device that normally makes two connections an hour
	// from being reported for making twenty. Proportionally enormous, in
	// practice nothing.
	minVolumeCount = 200
)

func (r VolumeAnomaly) Evaluate(ctx context.Context, in Input) ([]Observation, error) {
	if in.Baseline < volumeBaseline {
		return nil, nil
	}

	// Hourly connection counts per device across the history.
	rows, err := in.DB.QueryContext(ctx, `
SELECT COALESCE(NULLIF(f.device_id, ''), a.device_id, '') AS device_id,
       f.ts_start / 3600 AS hour,
       COUNT(*) AS n
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
WHERE f.ts_start >= ?
GROUP BY 1, 2
ORDER BY 1, 2`, in.Now.Add(-volumeHistory).Unix())
	if err != nil {
		return nil, fmt.Errorf("volume query: %w", err)
	}
	defer rows.Close()

	type series struct {
		counts   []float64
		lastHour int64
		lastN    float64
	}
	byDevice := map[string]*series{}
	currentHour := in.Now.Unix() / 3600

	for rows.Next() {
		var (
			deviceID string
			hour     int64
			n        float64
		)
		if err := rows.Scan(&deviceID, &hour, &n); err != nil {
			return nil, err
		}
		if deviceID == "" {
			continue
		}
		s := byDevice[deviceID]
		if s == nil {
			s = &series{}
			byDevice[deviceID] = s
		}
		// The hour in progress is incomplete and would always look quiet, so the
		// most recent *finished* hour is the one judged.
		if hour >= currentHour {
			continue
		}
		if hour > s.lastHour {
			s.lastHour, s.lastN = hour, n
		}
		s.counts = append(s.counts, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []Observation
	for deviceID, s := range byDevice {
		if len(s.counts) < minVolumeHours || s.lastN < minVolumeCount {
			continue
		}
		// The hour under test is excluded from its own baseline.
		history := make([]float64, 0, len(s.counts)-1)
		for i, v := range s.counts {
			if i == len(s.counts)-1 {
				continue
			}
			history = append(history, v)
		}

		med := median(history)
		spread := medianDeviation(history, med)
		// A device with a perfectly steady rate has no spread, and dividing by it
		// would call any change infinite. Half a connection is the floor.
		if spread < 0.5 {
			spread = 0.5
		}

		threshold := med + volumeMultiple*spread
		if s.lastN <= threshold {
			continue
		}

		out = append(out, Observation{
			Subject:     deviceID,
			SubjectType: "device",
			Score:       volumeScore(s.lastN, threshold),
			At:          time.Unix(s.lastHour*3600, 0),
			Detail: map[string]any{
				"connections": int(s.lastN),
				"typical":     int(med),
				"times":       round1(s.lastN / maxFloat(med, 1)),
			},
			// One busy hour per device per day. A device that is busy for three
			// hours running is one story.
			Dedup: "volume_anomaly:" + deviceID + ":" + time.Unix(s.lastHour*3600, 0).Format("2006-01-02"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dedup < out[j].Dedup })
	return out, nil
}

func volumeScore(observed, threshold float64) float64 {
	over := (observed - threshold) / threshold
	if over > 1 {
		over = 1
	}
	return Clamp(0.45 + 0.4*over)
}

// medianDeviation is the median absolute deviation from a centre, the robust
// counterpart to standard deviation.
func medianDeviation(values []float64, centre float64) float64 {
	if len(values) == 0 {
		return 0
	}
	devs := make([]float64, len(values))
	for i, v := range values {
		devs[i] = abs(v - centre)
	}
	return median(devs)
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
