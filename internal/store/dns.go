package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// DNS queries backing Radio Chatter.
//
// The feed is the raw stream; the aggregates are what make it useful. "Which
// domains does this network talk to most" and "which ones has it never asked for
// before" are the two questions that turn a scrolling log into something a
// person can act on.

// DNSOptions filters the DNS feed.
type DNSOptions struct {
	Since  time.Time
	Until  time.Time
	Device string
	// Domain matches the queried name, as a substring.
	Domain string
	// FlaggedOnly restricts results to names that matched a labelling list.
	FlaggedOnly bool
	Limit       int

	// Export lifts the feed ceiling. Set only by the export handler.
	Export bool
}

// FeedCeiling is the most rows the live feed will return however large a limit
// is asked for. It protects the endpoint from a caller asking for a million.
const FeedCeiling = 2000

func (o DNSOptions) limit() int {
	if o.Limit <= 0 {
		return 200
	}
	// An export is a deliberate act by somebody who wants their data, not a
	// screen refreshing every few seconds, so it is not held to the feed's
	// ceiling. It was: an export of a day's lookups returned 2000 of 48981 and
	// said nothing about the other 46981, in a file named as though it were the
	// lot. Silent truncation in an export is worse than a refusal.
	ceiling := FeedCeiling
	if o.Export {
		ceiling = ExportCeiling
	}
	if o.Limit > ceiling {
		return ceiling
	}
	return o.Limit
}

// DNSEvents returns the feed, newest first.
func (s *Store) DNSEvents(ctx context.Context, o DNSOptions) ([]types.DNSEvent, error) {
	where := []string{"1=1"}
	args := []any{}

	if !o.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, o.Since.Unix())
	}
	if !o.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, o.Until.Unix())
	}
	if o.Device != "" {
		where = append(where, "device_id = ?")
		args = append(args, o.Device)
	}
	if d := strings.TrimSpace(o.Domain); d != "" {
		where = append(where, "qname LIKE ?")
		args = append(args, "%"+strings.ToLower(d)+"%")
	}
	if o.FlaggedOnly {
		where = append(where, "flagged IS NOT NULL AND flagged != ''")
	}
	args = append(args, o.limit())

	rows, err := s.db.QueryContext(ctx, `
SELECT id, ts, COALESCE(device_id,''), COALESCE(process,''), qname, COALESCE(qtype,''),
       COALESCE(answers,''), COALESCE(resp_ms,0), COALESCE(flagged,'')
FROM dns_events
WHERE `+strings.Join(where, " AND ")+`
ORDER BY ts DESC, id DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []types.DNSEvent
	for rows.Next() {
		var (
			e       types.DNSEvent
			ts      int64
			answers string
		)
		if err := rows.Scan(&e.ID, &ts, &e.DeviceID, &e.Process, &e.QName,
			&e.QType, &answers, &e.RespMS, &e.Flagged); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		if answers != "" && answers != "null" {
			json.Unmarshal([]byte(answers), &e.Answers)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DomainSummary is one row of the top-domains aggregate.
type DomainSummary struct {
	Domain    string `json:"domain"`
	Lookups   int64  `json:"lookups"`
	Devices   int64  `json:"devices"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	Flagged   string `json:"flagged,omitempty"`
	// New marks a domain first seen inside the window being viewed, which is
	// what makes "something started talking to somewhere new" visible.
	New bool `json:"new"`
}

// TopDomains returns the most-queried domains in a window, marking any whose
// first-ever sighting falls inside it.
//
// The "new" flag is computed against the whole history rather than the window,
// because a domain queried every day for a month is not news, and one that
// appeared an hour ago is.
func (s *Store) TopDomains(ctx context.Context, since, until time.Time, limit int) ([]DomainSummary, error) {
	if limit <= 0 {
		limit = 25
	}
	if until.IsZero() {
		until = time.Now()
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT w.qname,
       COUNT(*)                          AS lookups,
       COUNT(DISTINCT w.device_id)        AS devices,
       (SELECT MIN(ts) FROM dns_events a WHERE a.qname = w.qname) AS first_ever,
       MAX(w.ts)                          AS last_seen,
       COALESCE(MAX(w.flagged), '')       AS flagged
FROM dns_events w
WHERE w.ts >= ? AND w.ts <= ?
GROUP BY w.qname
ORDER BY lookups DESC
LIMIT ?`, since.Unix(), until.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainSummary
	for rows.Next() {
		var d DomainSummary
		if err := rows.Scan(&d.Domain, &d.Lookups, &d.Devices,
			&d.FirstSeen, &d.LastSeen, &d.Flagged); err != nil {
			return nil, err
		}
		d.New = d.FirstSeen >= since.Unix()
		out = append(out, d)
	}
	return out, rows.Err()
}

// NewDomains returns domains whose first-ever lookup falls inside the window,
// most recent first.
//
// This is the query that answers "what has this network started talking to that
// it never did before", which is the DNS half of first-contact detection.
func (s *Store) NewDomains(ctx context.Context, since, until time.Time, limit int) ([]DomainSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	if until.IsZero() {
		until = time.Now()
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT qname, COUNT(*), COUNT(DISTINCT device_id), MIN(ts), MAX(ts), COALESCE(MAX(flagged), '')
FROM dns_events
GROUP BY qname
HAVING MIN(ts) >= ? AND MIN(ts) <= ?
ORDER BY MIN(ts) DESC
LIMIT ?`, since.Unix(), until.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainSummary
	for rows.Next() {
		var d DomainSummary
		if err := rows.Scan(&d.Domain, &d.Lookups, &d.Devices,
			&d.FirstSeen, &d.LastSeen, &d.Flagged); err != nil {
			return nil, err
		}
		d.New = true
		out = append(out, d)
	}
	return out, rows.Err()
}

// DNSStats is the header summary for Radio Chatter.
type DNSStats struct {
	Lookups    int64 `json:"lookups"`
	Domains    int64 `json:"domains"`
	NewDomains int64 `json:"new_domains"`
	Flagged    int64 `json:"flagged"`
	Devices    int64 `json:"devices"`
}

// DNSSummary counts the DNS activity in a window.
func (s *Store) DNSSummary(ctx context.Context, since, until time.Time) (DNSStats, error) {
	if until.IsZero() {
		until = time.Now()
	}
	var st DNSStats

	row := s.db.QueryRowContext(ctx, `
SELECT (SELECT COUNT(*) FROM dns_events WHERE ts BETWEEN ? AND ?),
       (SELECT COUNT(DISTINCT qname) FROM dns_events WHERE ts BETWEEN ? AND ?),
       (SELECT COUNT(*) FROM (
           SELECT qname FROM dns_events GROUP BY qname HAVING MIN(ts) BETWEEN ? AND ?
        )),
       (SELECT COUNT(*) FROM dns_events
         WHERE ts BETWEEN ? AND ? AND flagged IS NOT NULL AND flagged != ''),
       (SELECT COUNT(DISTINCT device_id) FROM dns_events
         WHERE ts BETWEEN ? AND ? AND device_id != '')`,
		since.Unix(), until.Unix(), since.Unix(), until.Unix(),
		since.Unix(), until.Unix(), since.Unix(), until.Unix(),
		since.Unix(), until.Unix())

	err := row.Scan(&st.Lookups, &st.Domains, &st.NewDomains, &st.Flagged, &st.Devices)
	return st, err
}

// LabelDNS applies a category to every stored lookup of a domain and its
// subdomains.
//
// Labelling happens after the fact rather than at ingest, so that adding or
// updating a list re-labels history rather than only affecting what arrives
// next. Nothing is ever blocked: the label is information, not enforcement.
func (s *Store) LabelDNS(ctx context.Context, domain, category string) (int64, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || category == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE dns_events SET flagged = ?
WHERE (qname = ? OR qname LIKE ?) AND (flagged IS NULL OR flagged = '')`,
		category, domain, "%."+domain)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
