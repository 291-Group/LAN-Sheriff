package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Retention bounds how much history is kept. The defaults are chosen to be safe
// on a Raspberry Pi left running for weeks; both limits
// are enforced, size first.
type Retention struct {
	Raw      time.Duration // full-resolution flows and DNS events
	Rollup   time.Duration // hourly aggregates
	MaxBytes int64         // hard cap on the database file
	Interval time.Duration // how often the pruner runs
}

// DefaultRetention is the Pi-safe default.
func DefaultRetention() Retention {
	return Retention{
		Raw:      72 * time.Hour,
		Rollup:   365 * 24 * time.Hour,
		MaxBytes: 512 << 20,
		Interval: 5 * time.Minute,
	}
}

// PruneStats reports what one pass removed.
type PruneStats struct {
	Flows     int64
	DNSEvents int64
	Endpoints int64
	Rollups   int64
	Findings  int64
	Bytes     int64
	OverCap   bool
}

// Prune enforces the retention policy. Age limits are applied first; if the
// database is still over its size cap, the oldest raw data is dropped in
// batches until it fits, and only then are rollups touched, losing detail
// before losing the long trend line.
func (s *Store) Prune(ctx context.Context, r Retention) (PruneStats, error) {
	var st PruneStats
	now := time.Now()

	rawCutoff := now.Add(-r.Raw).Unix()
	n, err := s.exec(ctx, `DELETE FROM flows WHERE ts_last < ?`, rawCutoff)
	if err != nil {
		return st, err
	}
	st.Flows += n

	if n, err = s.exec(ctx, `DELETE FROM dns_events WHERE ts < ?`, rawCutoff); err != nil {
		return st, err
	}
	st.DNSEvents += n

	rollupCutoff := now.Add(-r.Rollup).Unix()
	if n, err = s.exec(ctx, `DELETE FROM rollups WHERE bucket_ts < ?`, rollupCutoff); err != nil {
		return st, err
	}
	st.Rollups += n

	// Endpoints outlive their flows so the map keeps its labels, but an endpoint
	// with no remaining flows and nothing recent is just dead weight.
	if n, err = s.exec(ctx, `
DELETE FROM endpoints
WHERE last_seen < ? AND ip NOT IN (SELECT DISTINCT dst_ip FROM flows)`, rawCutoff); err != nil {
		return st, err
	}
	st.Endpoints += n

	if n, err = s.exec(ctx, `DELETE FROM findings WHERE ts < ? AND status != 'open'`, rawCutoff); err != nil {
		return st, err
	}
	st.Findings += n

	// Size cap: walk the raw tier forward in time until the file fits.
	if r.MaxBytes > 0 {
		for pass := 0; pass < 20; pass++ {
			size, err := s.fileSize()
			if err != nil || size <= r.MaxBytes {
				break
			}
			st.OverCap = true
			if pass == 0 {
				slog.Warn("database over size cap, pruning oldest raw data",
					"size_bytes", size, "cap_bytes", r.MaxBytes)
			}
			// Drop the oldest 10% of flows per pass. VACUUM is what actually
			// returns the space, so it has to run inside the loop.
			n, err := s.exec(ctx, `
DELETE FROM flows WHERE id IN (
  SELECT id FROM flows ORDER BY ts_last ASC LIMIT MAX(1, (SELECT COUNT(*)/10 FROM flows)))`)
			if err != nil {
				return st, err
			}
			st.Flows += n
			if _, err := s.exec(ctx, `DELETE FROM dns_events WHERE id IN (
  SELECT id FROM dns_events ORDER BY ts ASC LIMIT MAX(1, (SELECT COUNT(*)/10 FROM dns_events)))`); err != nil {
				return st, err
			}
			if n == 0 {
				break // nothing left to give
			}
			if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
				return st, fmt.Errorf("vacuum: %w", err)
			}
		}
	}

	if size, err := s.fileSize(); err == nil {
		st.Bytes = size
	}
	return st, nil
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *Store) fileSize() (int64, error) {
	fi, err := os.Stat(s.path)
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	// The WAL can be a large share of on-disk usage, so count it against the cap.
	if wal, err := os.Stat(s.path + "-wal"); err == nil {
		size += wal.Size()
	}
	return size, nil
}

// optimize refreshes the query planner's statistics.
//
// **This is worth more than any index in this schema, and it was missing.**
//
// Without statistics SQLite plans the Watchtower's own query by scanning every
// flow in the window and building a temporary B-tree to group it. With them it
// scans the endpoints table, which is three orders of magnitude smaller, and
// probes flows by destination. Measured through this driver against 78,698
// flows and 450 endpoints: **304ms before, 94ms after**, for the seven-day map.
// On a Raspberry Pi 3B+, where the same query took 7.7 seconds, that is the
// difference between a view and a timeout.
//
// A covering index on (direction, ts_last, dst_ip) was tried first and is not
// here because it changed nothing: 307ms without statistics and 94ms with them,
// index or no index. The planner was not short of an access path, it was short
// of any reason to believe one was better, and an index added on that mistaken
// diagnosis would have cost a write on every flow forever.
//
// PRAGMA optimize rather than a bare ANALYZE: it is SQLite's own recommendation
// for exactly this, and it re-analyses only the tables whose statistics have
// gone stale, so on a database that has settled it does nothing at all.
//
// Runs after pruning because that is when the shape of the data has just
// changed the most, and because a failure here is not worth interrupting
// anything for: stale statistics make queries slower, not wrong.
func (s *Store) optimize(ctx context.Context) {
	if _, err := s.db.ExecContext(ctx, `PRAGMA optimize`); err != nil && ctx.Err() == nil {
		slog.Debug("could not refresh query statistics", "err", err)
	}
}

// analyzeIfNeverAnalysed runs a full ANALYZE the first time a database is
// opened without any statistics at all.
//
// PRAGMA optimize cannot do this job. It decides what to re-analyse from the
// tables the *current connection* has already queried, so on a connection that
// has run nothing it correctly concludes there is nothing to do, and an
// instance restarted over an existing database served its first hours of
// requests on empty statistics. Measured: PRAGMA optimize at open left the
// seven-day map query at 304ms, exactly the unanalysed number.
//
// Guarded on sqlite_stat1 being absent or empty, so this is once in the life of
// a database rather than a cost at every start. After that the pruner's
// PRAGMA optimize keeps them current, which is the job it is actually good at.
func (s *Store) analyzeIfNeverAnalysed(ctx context.Context) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sqlite_stat1'`).Scan(&n)
	if err == nil && n > 0 {
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_stat1`).Scan(&n); err == nil && n > 0 {
			return // already has statistics
		}
	}
	if _, err := s.db.ExecContext(ctx, `ANALYZE`); err != nil && ctx.Err() == nil {
		slog.Debug("could not build query statistics", "err", err)
	}
}

// RunPruner prunes on a schedule until the context is cancelled.
//
// The policy is fetched fresh on every pass rather than captured once, so
// changing retention in settings takes effect without a restart.
func (s *Store) RunPruner(ctx context.Context, policy func() Retention) {
	interval := policy().Interval
	if interval <= 0 {
		interval = DefaultRetention().Interval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r := policy()
			st, err := s.Prune(ctx, r)
			if err != nil {
				slog.Error("prune failed", "err", err)
				continue
			}
			if st.Flows > 0 || st.DNSEvents > 0 {
				slog.Debug("pruned", "flows", st.Flows, "dns", st.DNSEvents,
					"bytes", st.Bytes, "over_cap", st.OverCap)
			}
			s.optimize(ctx)
		}
	}
}
