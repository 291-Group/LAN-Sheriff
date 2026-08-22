package store

import (
	"context"
	"database/sql"
	"time"
)

// The at-a-glance figures for the sidebar.
//
// These exist to answer one question: has anything changed since I last looked?
// That is the question that makes somebody open a network monitor at all, and
// none of the main views answer it, they show what is happening, not what is
// different.
//
// So the figures are all comparative or superlative: what is new, what is
// loudest, when the network is quiet. A count of total connections would be a
// number nobody can act on.

// Glance is the sidebar summary.
type Glance struct {
	// NewOrgs is organizations contacted for the first time within the window.
	NewOrgs int64 `json:"new_orgs"`
	// NewDevices is devices seen for the first time within the window.
	NewDevices int64 `json:"new_devices"`

	// Loudest names the device accounting for the most connections in the
	// window, which on most networks is not the one people expect.
	LoudestDevice string `json:"loudest_device,omitempty"`
	LoudestID     string `json:"loudest_id,omitempty"`
	LoudestConns  int64  `json:"loudest_conns,omitempty"`

	// QuietestHour is the hour of the local day with the least traffic, over a
	// longer window than the rest, a single day says nothing about habit.
	// Negative means not enough history to say.
	QuietestHour  int   `json:"quietest_hour"`
	QuietestConns int64 `json:"quietest_conns"`

	// DevicesOnline and DevicesKnown put the roster in one line.
	DevicesOnline int64 `json:"devices_online"`
	DevicesKnown  int64 `json:"devices_known"`

	// Window is how far back the "new" and "loudest" figures look.
	Window string `json:"window"`
}

// GlanceWindow is the period the tally covers.
//
// A day rather than an hour: the point is "since I last looked", and most people
// do not look hourly. It also spans a night, which is when a household network
// is most revealing about what runs without anybody present.
const GlanceWindow = 24 * time.Hour

// quietestHourWindow is deliberately longer. One day's quiet hour is an
// accident of that day; a week's is a habit, and a habit is what makes a
// departure from it worth noticing.
const quietestHourWindow = 7 * 24 * time.Hour

// Glance computes the sidebar summary.
func (s *Store) Glance(ctx context.Context, now time.Time) (Glance, error) {
	g := Glance{QuietestHour: -1, Window: "24h"}
	since := now.Add(-GlanceWindow).Unix()

	// An organization is "new" when the first endpoint attributed to it was first
	// seen inside the window. Endpoints carry the timestamp; organizations are
	// not stored separately.
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM (
  SELECT COALESCE(NULLIF(org, ''), NULLIF(country_name, ''), NULLIF(country, '')) AS o,
         MIN(first_seen) AS seen
  FROM endpoints
  WHERE is_internal = 0 AND COALESCE(NULLIF(org, ''), NULLIF(country, '')) IS NOT NULL
  GROUP BY o
  HAVING seen >= ?
)`, since).Scan(&g.NewOrgs); err != nil {
		return g, err
	}

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE first_seen >= ?`, since).Scan(&g.NewDevices); err != nil {
		return g, err
	}

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(online), 0) FROM devices`).
		Scan(&g.DevicesKnown, &g.DevicesOnline); err != nil {
		return g, err
	}

	// The loudest device, by connections rather than bytes: Deputy Mode reads
	// socket tables, which carry no byte counts, so bytes would report zero on
	// most installs and look broken.
	var (
		id    sql.NullString
		label sql.NullString
		conns sql.NullInt64
	)
	// Resolved through device_addresses, not taken from the flow.
	//
	// Patrol Mode tags a flow `lan-<ip>` until something establishes which
	// machine holds that address. Grouping on the raw value therefore split one
	// device's traffic between its placeholder and its real identity, reporting
	// the busiest device as less busy than it is, and could label the widget
	// `lan-192.168.68.58`, which means nothing to anybody.
	//
	// GROUP BY is positional: SQLite resolves a bare name against the output
	// aliases before the input columns, which has silently grouped by the wrong
	// thing in this codebase before.
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(a.device_id, f.device_id) AS did,
       COALESCE(NULLIF(d.label, ''), NULLIF(d.name, ''), NULLIF(d.hostname, ''),
                NULLIF(d.model, ''), NULLIF(d.ip, ''), COALESCE(a.device_id, f.device_id)),
       COUNT(*) AS n
FROM flows f
LEFT JOIN device_addresses a ON a.ip = f.src_ip
LEFT JOIN devices d ON d.id = COALESCE(a.device_id, f.device_id)
WHERE f.ts_last >= ?
  AND COALESCE(a.device_id, f.device_id) IS NOT NULL
  AND COALESCE(a.device_id, f.device_id) != ''
GROUP BY 1
ORDER BY n DESC
LIMIT 1`, since).Scan(&id, &label, &conns)
	if err != nil && err != sql.ErrNoRows {
		return g, err
	}
	if id.Valid {
		g.LoudestID, g.LoudestDevice, g.LoudestConns = id.String, label.String, conns.Int64
	}

	// The quietest hour needs enough history to mean anything. Without a full
	// day there is no comparison to make, and reporting the emptiest hour of a
	// half-hour-old database would be noise dressed as insight.
	var span int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ts_last) - MIN(ts_last), 0) FROM flows`).Scan(&span); err != nil {
		return g, err
	}
	if span < int64((24 * time.Hour).Seconds()) {
		return g, nil
	}

	// The local-time offset is computed once, in Go, and the bucket is integer
	// arithmetic. It used to be `strftime('%H', ts_last, 'unixepoch',
	// 'localtime')`, which is correct and which SQLite evaluates **per row**:
	// this query groups every flow in a seven-day window, so on a week of real
	// traffic that is a string format and a timezone lookup tens of thousands of
	// times to produce one number for a sidebar widget.
	//
	// Measured against 78,698 flows through this driver: 528ms, against 23ms for
	// the arithmetic below and 1ms for a bare count over the same rows. It is by
	// some distance the most expensive thing in Glance, and it costs more than
	// the map query it sits beside. The reason it hurts here in particular is
	// that this build uses a pure-Go SQLite, which is roughly ten times the
	// per-row cost of the C library, so anything evaluated per row is worth
	// about ten times what it looks like.
	//
	// **What is given up.** strftime resolves the offset for each timestamp, so
	// it follows a daylight-saving change through the window; a single offset
	// does not. Across a DST boundary some flows land in the neighbouring hour.
	// For "quietest around 2 AM", drawn from a week of history and rounded to an
	// hour anyway, twice a year one bucket is off by one. That is a fair price
	// for the sidebar not costing half a second, and it is a real difference
	// rather than none, which is why it is written down.
	_, zoneOffset := now.Zone()
	rows, err := s.db.QueryContext(ctx, `
SELECT ((ts_last + ?) / 3600) % 24 AS hour, COUNT(*) AS n
FROM flows
WHERE ts_last >= ?
GROUP BY hour
ORDER BY n ASC
LIMIT 1`, zoneOffset, now.Add(-quietestHourWindow).Unix())
	if err != nil {
		return g, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&g.QuietestHour, &g.QuietestConns); err != nil {
			return g, err
		}
	}
	return g, rows.Err()
}
