package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Findings: things worth a second look.
//
// A finding is a claim the application makes about something it observed, and
// every one has to survive the same test: would a person be glad it interrupted
// them? A finding nobody acts on trains people to ignore the next one, which
// costs more than never having raised it.

// Rule codes. Stable identifiers, the dashboard translates them, and they are
// stored, so renaming one changes historical data.
const (
	// RuleNewDevice fires when a device appears that this network has not seen
	// before.
	RuleNewDevice = "new_device"
)

// Finding statuses.
const (
	FindingOpen    = "open"
	FindingCleared = "cleared"
	FindingTrusted = "trusted"
)

// Finding is one recorded observation worth surfacing.
type Finding struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	Subject string    `json:"subject"`
	// SubjectType is "device" or "endpoint".
	SubjectType string  `json:"subject_type"`
	Rule        string  `json:"rule"`
	Score       float64 `json:"score"`
	// Detail carries rule-specific facts as JSON, so the UI can explain the
	// finding in the viewer's language rather than storing English prose.
	Detail map[string]any `json:"detail,omitempty"`
	Status string         `json:"status"`
	// Label is the subject's display name, resolved at read time so a device
	// renamed after the finding was raised shows its current name.
	Label string `json:"label,omitempty"`
}

// baselineKey records when this install first took stock of the network.
const baselineKey = "roster_baseline_at"

// baselineGrace is how long after first start the Roster is treated as a census
// rather than a stream of arrivals.
//
// Everything on the network is "new" to an empty database, and raising a finding
// for each would fill the Wanted List with the user's own household on day one,
// the fastest possible way to teach somebody that these alerts are worthless.
// Discovery needs a couple of minutes to find what is already there; ten gives
// it room on a slow or busy network.
const baselineGrace = 10 * time.Minute

// markBaseline records when this install began observing, if it has not already.
//
// Called from Open rather than from the first device creation. Doing it lazily
// looked equivalent and was not: on a database that already knows every device,
// no creation happens, so the baseline stayed unset, and then the first genuine
// arrival months later would set the baseline to that moment and be swallowed by
// its own grace period. The one arrival the feature exists for would be the one
// it missed.
//
// Setting it at startup also gives an upgraded install a fresh grace window, so
// re-discovering a known network after an update raises nothing.
func (s *Store) markBaseline(now time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
		baselineKey, strconv.FormatInt(now.Unix(), 10))
	return err
}

// baselineAt returns when this install began observing.
func (s *Store) baselineAt(ctx context.Context, tx *sql.Tx, now time.Time) (time.Time, error) {
	var v string
	err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, baselineKey).Scan(&v)
	switch {
	case err == sql.ErrNoRows:
		// Open sets this, so reaching here means a store built by hand in a
		// test. Treating now as the baseline is the safe reading: it suppresses
		// rather than invents.
		return now, nil
	case err != nil:
		return time.Time{}, err
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return now, nil
	}
	return time.Unix(sec, 0), nil
}

// recordNewDevice raises a finding for a device that has genuinely just arrived.
//
// Called from inside the observation transaction, so a finding cannot exist for
// a device that was never committed.
func (s *Store) recordNewDevice(ctx context.Context, tx *sql.Tx, id string, o types.Sighting) error {
	// This machine is not an arrival.
	if o.IsSelf {
		return nil
	}

	base, err := s.baselineAt(ctx, tx, o.SeenAt)
	if err != nil {
		return err
	}
	if o.SeenAt.Before(base.Add(baselineGrace)) {
		return nil // still taking the census
	}

	detail := map[string]any{}
	if o.MAC != "" {
		detail["mac"] = o.MAC
	}
	if o.Vendor != "" {
		detail["vendor"] = o.Vendor
	}
	if o.IP != "" {
		detail["ip"] = o.IP
	}
	if o.Hostname != "" {
		detail["hostname"] = o.Hostname
	}
	if o.Source != "" {
		detail["source"] = o.Source
	}
	blob, err := json.Marshal(detail)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO findings (ts, last_seen, subject_type, subject, rule, score, detail, status)
VALUES (?, ?, 'device', ?, ?, ?, ?, ?)`,
		o.SeenAt.Unix(), o.SeenAt.Unix(), id, RuleNewDevice,
		newDeviceScore(o), string(blob), FindingOpen); err != nil {
		return err
	}

	// A device arriving is always new by definition, so it is announced without
	// the dedup check the rule engine needs.
	if s.OnFinding != nil {
		label := o.Hostname
		if label == "" {
			label = o.IP
		}
		if label == "" {
			label = o.MAC
		}
		s.OnFinding(RuleNewDevice, label, newDeviceScore(o))
	}
	return nil
}

// newDeviceScore rates how much attention an arrival deserves.
//
// A device that names itself and has a recognisable manufacturer is more likely
// to be a phone someone brought home than something worth investigating. One
// that offers no identification at all is the more interesting case, so it
// scores higher, the score orders the list, it does not accuse anybody.
func newDeviceScore(o types.Sighting) float64 {
	score := 0.5
	if o.Vendor == "" {
		score += 0.2
	}
	if o.Hostname == "" && o.Name == "" {
		score += 0.2
	}
	if score > 1 {
		score = 1
	}
	return score
}

// Findings returns recorded findings, newest first.
func (s *Store) Findings(ctx context.Context, status string, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
SELECT f.id, f.ts, f.subject_type, f.subject, f.rule, f.score,
       COALESCE(f.detail, ''), f.status,
       COALESCE(NULLIF(d.label, ''), NULLIF(d.name, ''), NULLIF(d.hostname, ''),
                NULLIF(d.model, ''), NULLIF(d.ip, ''), '')
FROM findings f
LEFT JOIN devices d ON d.id = f.subject AND f.subject_type = 'device'`
	args := []any{}
	if status != "" {
		q += ` WHERE f.status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY f.ts DESC, f.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Finding{}
	for rows.Next() {
		var (
			f      Finding
			ts     int64
			detail string
		)
		if err := rows.Scan(&f.ID, &ts, &f.SubjectType, &f.Subject, &f.Rule,
			&f.Score, &detail, &f.Status, &f.Label); err != nil {
			return nil, err
		}
		f.TS = time.Unix(ts, 0)
		if detail != "" {
			// A malformed detail blob must not lose the finding itself.
			_ = json.Unmarshal([]byte(detail), &f.Detail)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFindingStatus clears or trusts a finding.
func (s *Store) SetFindingStatus(ctx context.Context, id int64, status string) error {
	switch status {
	case FindingOpen, FindingCleared, FindingTrusted:
	default:
		return errBadStatus
	}
	res, err := s.db.ExecContext(ctx, `UPDATE findings SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrFindingNotFound
	}
	return nil
}

type findingError string

func (e findingError) Error() string { return string(e) }

// ErrFindingNotFound is returned when a status change names a finding that does
// not exist.
const ErrFindingNotFound = findingError("finding not found")

const errBadStatus = findingError("unknown finding status")

// BaselineAt reports when this install began observing.
//
// Exposed so the suspicion engine can tell how much history it is reasoning
// about. A rule that decides what is normal here has to know whether "here" has
// been watched for a day or a month.
func (s *Store) BaselineAt(ctx context.Context) time.Time {
	var v string
	if err := s.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = ?`, baselineKey).Scan(&v); err != nil {
		return time.Now()
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Now()
	}
	return time.Unix(sec, 0)
}
