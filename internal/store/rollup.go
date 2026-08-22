package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Rollups are the long tail of history. Raw flows live for days; these hourly
// aggregates live for a year, at a tiny fraction of the size, and are what make
// it cheap to scrub back through weeks of activity.
//
// The writer only ever processes *complete* hours. Aggregating the current hour
// would produce a bucket that keeps changing, and re-running would double-count
// it. Progress is recorded so a restart resumes rather than redoing work.

// rollupCursorKey records the last hour bucket that has been aggregated.
const rollupCursorKey = "rollup.cursor"

// RollupKind identifies what a rollup row counts.
const (
	RollupEndpoint = "endpoint"
	RollupOrg      = "org"
	RollupDevice   = "device"
	RollupProcess  = "process"
	RollupCountry  = "country"
)

// hourBucket truncates a time to the hour it falls in.
func hourBucket(t time.Time) int64 {
	return t.Truncate(time.Hour).Unix()
}

// Rollup aggregates every complete hour that has not been aggregated yet.
// It returns the number of buckets processed.
func (s *Store) Rollup(ctx context.Context, now time.Time) (int, error) {
	currentBucket := hourBucket(now)

	cursor, err := s.rollupCursor(ctx)
	if err != nil {
		return 0, err
	}
	if cursor == 0 {
		// First run: start from the oldest flow we hold rather than the epoch.
		var oldest int64
		row := s.db.QueryRowContext(ctx, `SELECT COALESCE(MIN(ts_start), 0) FROM flows`)
		if err := row.Scan(&oldest); err != nil {
			return 0, err
		}
		if oldest == 0 {
			return 0, nil // nothing stored yet
		}
		cursor = hourBucket(time.Unix(oldest, 0)) - 3600
	}

	var done int
	for bucket := cursor + 3600; bucket < currentBucket; bucket += 3600 {
		if err := s.rollupBucket(ctx, bucket); err != nil {
			return done, fmt.Errorf("rollup bucket %d: %w", bucket, err)
		}
		if err := s.SetSetting(ctx, rollupCursorKey, fmt.Sprint(bucket)); err != nil {
			return done, err
		}
		done++
		// A long-idle instance could have thousands of empty buckets to walk;
		// yield rather than hold the database for minutes.
		if done >= 500 {
			break
		}
	}
	return done, nil
}

func (s *Store) rollupCursor(ctx context.Context) (int64, error) {
	v, ok, err := s.Setting(ctx, rollupCursorKey)
	if err != nil || !ok {
		return 0, err
	}
	var n int64
	fmt.Sscanf(v, "%d", &n)
	return n, nil
}

// rollupBucket aggregates one hour into the rollups table.
//
// Flows are counted in the bucket they were last seen in, which keeps a
// long-lived connection in one place rather than smeared across every hour it
// spanned. For the trend views this reads correctly and costs nothing.
func (s *Store) rollupBucket(ctx context.Context, bucket int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Replace rather than add, so re-running a bucket is idempotent.
	if _, err := tx.ExecContext(ctx, `DELETE FROM rollups WHERE bucket_ts = ?`, bucket); err != nil {
		return err
	}

	sources := []struct {
		kind string
		expr string
		join string
	}{
		{RollupEndpoint, "f.dst_ip", ""},
		{RollupOrg, "COALESCE(NULLIF(e.org, ''), 'unknown')", "JOIN endpoints e ON e.ip = f.dst_ip"},
		{RollupCountry, "COALESCE(NULLIF(e.country, ''), 'unknown')", "JOIN endpoints e ON e.ip = f.dst_ip"},
		{RollupDevice, "COALESCE(NULLIF(f.device_id, ''), 'unknown')", ""},
		{RollupProcess, "COALESCE(NULLIF(f.process, ''), 'unknown')", ""},
	}

	for _, src := range sources {
		q := fmt.Sprintf(`
INSERT INTO rollups (bucket_ts, key_type, key, conns, bytes_out, bytes_in)
SELECT ?, ?, %s, COUNT(*), COALESCE(SUM(f.bytes_out), 0), COALESCE(SUM(f.bytes_in), 0)
FROM flows f %s
WHERE f.ts_last >= ? AND f.ts_last < ?
GROUP BY %s`, src.expr, src.join, src.expr)

		if _, err := tx.ExecContext(ctx, q, bucket, src.kind, bucket, bucket+3600); err != nil {
			return fmt.Errorf("%s: %w", src.kind, err)
		}
	}
	return tx.Commit()
}

// RunRollups aggregates on a schedule until the context is cancelled.
func (s *Store) RunRollups(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Minute
	}
	// Catch up once at startup, so a restart after downtime does not wait.
	if n, err := s.Rollup(ctx, time.Now()); err != nil {
		slog.Warn("rollup failed", "err", err)
	} else if n > 0 {
		slog.Debug("rolled up history", "buckets", n)
	}

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Rollup(ctx, time.Now()); err != nil {
				slog.Warn("rollup failed", "err", err)
			}
		}
	}
}

// TimePoint is one bucket of the activity timeline.
type TimePoint struct {
	TS        int64  `json:"ts"`
	Conns     int64  `json:"conns"`
	BytesOut  uint64 `json:"bytes_out"`
	BytesIn   uint64 `json:"bytes_in"`
	Endpoints int64  `json:"endpoints"`
}

// Timeline returns hourly activity between two times, for the scrub control.
//
// Recent hours are computed from raw flows, which is exact; older hours come
// from the rollups, which is what lets the range extend far past the raw
// retention window without keeping the flows themselves.
func (s *Store) Timeline(ctx context.Context, since, until time.Time) ([]TimePoint, error) {
	if until.IsZero() {
		until = time.Now()
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT bucket_ts, SUM(conns), SUM(bytes_out), SUM(bytes_in), COUNT(*)
FROM rollups
WHERE key_type = ? AND bucket_ts >= ? AND bucket_ts <= ?
GROUP BY bucket_ts ORDER BY bucket_ts`,
		RollupEndpoint, hourBucket(since), hourBucket(until))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byBucket := map[int64]*TimePoint{}
	var out []TimePoint
	for rows.Next() {
		var p TimePoint
		if err := rows.Scan(&p.TS, &p.Conns, &p.BytesOut, &p.BytesIn, &p.Endpoints); err != nil {
			return nil, err
		}
		cp := p
		byBucket[p.TS] = &cp
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The current hour, and any hour not yet rolled up, still has its raw flows.
	raw, err := s.db.QueryContext(ctx, `
SELECT (ts_last / 3600) * 3600 AS bucket, COUNT(*), COALESCE(SUM(bytes_out),0),
       COALESCE(SUM(bytes_in),0), COUNT(DISTINCT dst_ip)
FROM flows
WHERE ts_last >= ? AND ts_last <= ?
GROUP BY bucket ORDER BY bucket`, since.Unix(), until.Unix())
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	for raw.Next() {
		var p TimePoint
		if err := raw.Scan(&p.TS, &p.Conns, &p.BytesOut, &p.BytesIn, &p.Endpoints); err != nil {
			return nil, err
		}
		// Raw wins: it is exact, and the rollup for this hour may be partial.
		cp := p
		byBucket[p.TS] = &cp
	}
	if err := raw.Err(); err != nil {
		return nil, err
	}

	for b := hourBucket(since); b <= hourBucket(until); b += 3600 {
		if p, ok := byBucket[b]; ok {
			out = append(out, *p)
		} else {
			out = append(out, TimePoint{TS: b})
		}
	}
	return out, nil
}
