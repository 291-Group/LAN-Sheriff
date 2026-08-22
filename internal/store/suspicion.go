package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/suspicion"
)

// Writing what the rules found.
//
// The store is the only place that writes findings, and it is deliberately dumb
// about them: it records what a rule claimed and does not second-guess it. The
// judgement lives in the rules, where it can be read.

// QueryContext satisfies suspicion.Queryer, giving rules a read-only view.
func (s *Store) QueryContext(ctx context.Context, query string, args ...any) (suspicion.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}

// RecordObservations writes a rule's findings.
//
// A finding already raised is refreshed rather than repeated: its last_seen
// moves and its score takes the higher of the two, so behaviour that gets worse
// climbs the list while behaviour that merely continues does not accumulate.
func (s *Store) RecordObservations(
	ctx context.Context, rule string, weight float64, obs []suspicion.Observation,
) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rolled back only if Commit did not run

	// Which of these already exist, so that only genuinely new findings are
	// announced. The upsert cannot tell us afterwards, and notifying on every
	// refresh would mean a message every five minutes for as long as a
	// behaviour continues.
	fresh := make([]suspicion.Observation, 0, len(obs))
	for _, o := range obs {
		if o.Dedup == "" {
			fresh = append(fresh, o)
			continue
		}
		var exists int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM findings WHERE dedup = ?`, o.Dedup).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			fresh = append(fresh, o)
		}
	}

	for _, o := range obs {
		detail, err := json.Marshal(o.Detail)
		if err != nil {
			return err
		}
		at := o.At
		if at.IsZero() {
			at = time.Now()
		}
		score := suspicion.Clamp(o.Score) * weight

		if _, err := tx.ExecContext(ctx, `
INSERT INTO findings (ts, last_seen, subject_type, subject, rule, score, detail, status, dedup)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
-- The conflict target repeats the index's predicate: the unique index on dedup
-- is partial (empty keys are allowed to repeat, since a finding without one is
-- not deduplicated), and SQLite requires the target to match the index exactly.
ON CONFLICT(dedup) WHERE dedup != '' DO UPDATE SET
  last_seen = MAX(findings.last_seen, excluded.last_seen),
  -- Behaviour that becomes worse climbs; behaviour that merely persists does
  -- not accumulate into a false crescendo.
  score     = MAX(findings.score, excluded.score),
  detail    = excluded.detail`,
			at.Unix(), at.Unix(), o.SubjectType, o.Subject, rule,
			score, string(detail), FindingOpen, o.Dedup); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// Announced only after the transaction commits, so nothing is reported that
	// was then rolled back.
	for _, o := range fresh {
		s.announce(ctx, rule, o.Subject, suspicion.Clamp(o.Score)*weight)
	}
	return nil
}

// announce tells the notifier about a new finding, if one is configured.
//
// The subject's label is resolved here rather than in the notifier, because the
// notifier deliberately knows nothing about the database, it receives a name
// and a rule and nothing else.
func (s *Store) announce(ctx context.Context, rule, subject string, score float64) {
	if s.OnFinding == nil {
		return
	}
	label := subject
	var name string
	if err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(NULLIF(label, ''), NULLIF(name, ''), NULLIF(hostname, ''),
                NULLIF(model, ''), NULLIF(ip, ''), id)
FROM devices WHERE id = ?`, subject).Scan(&name); err == nil && name != "" {
		label = name
	}
	s.OnFinding(rule, label, score)
}

// SubjectSuspicion is a subject's total score across its open findings.
type SubjectSuspicion struct {
	Subject     string  `json:"subject"`
	SubjectType string  `json:"subject_type"`
	Label       string  `json:"label,omitempty"`
	Score       float64 `json:"score"`
	Findings    int     `json:"findings"`
}

// Wanted returns subjects ranked by how much is open against them.
//
// Scores combine additively and are capped at 1. Several weak signals about one
// device is the case worth surfacing, a single weak signal is not, and this is
// what stops any one rule from dominating the list on its own.
func (s *Store) Wanted(ctx context.Context, limit int) ([]SubjectSuspicion, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT f.subject, f.subject_type,
       COALESCE(NULLIF(d.label, ''), NULLIF(d.name, ''), NULLIF(d.hostname, ''),
                NULLIF(d.model, ''), NULLIF(d.ip, ''), ''),
       MIN(1.0, SUM(f.score)) AS total,
       COUNT(*) AS n
FROM findings f
LEFT JOIN devices d ON d.id = f.subject AND f.subject_type = 'device'
WHERE f.status = ?
GROUP BY f.subject, f.subject_type
ORDER BY total DESC, n DESC
LIMIT ?`, FindingOpen, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SubjectSuspicion{}
	for rows.Next() {
		var w SubjectSuspicion
		if err := rows.Scan(&w.Subject, &w.SubjectType, &w.Label, &w.Score, &w.Findings); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ExpireFindings closes findings that have not been seen for a while.
//
// A finding is a claim about current behaviour. One that stopped happening a
// week ago is history, and leaving it open would mean the Wanted List slowly
// becomes a list of everything that ever happened, which is the same as a list
// of nothing.
func (s *Store) ExpireFindings(ctx context.Context, now time.Time, after time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE findings SET status = ?
WHERE status = ? AND MAX(ts, last_seen) < ?`,
		FindingCleared, FindingOpen, now.Add(-after).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FindingTTL is how long a finding stays open without being seen again.
const FindingTTL = 7 * 24 * time.Hour

// The store must satisfy both halves of the engine's contract.
var (
	_ suspicion.Sink    = (*Store)(nil)
	_ suspicion.Queryer = (*Store)(nil)
)
