package store

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"modernc.org/sqlite"
)

// **Slow storage is a condition to live with, not a fault to report.**
//
// The first install on a router ran from an SD card that stalled for seconds
// at a stretch under sustained writes. Every writer in the process saw
// `database is locked (5)` for a minute at a time, and every one of them
// dropped what it was holding: flows, lookups, sightings and presence, on
// the one vantage point where the record matters most.
//
// Two answers, for two kinds of writer. The capture pipeline stages its work
// in memory, so it keeps a failed batch and offers it again on its own
// schedule (see pipeline.Engine); its writes are not retried here, because a
// retry would only hold the ingest goroutine longer for the same result. The
// writers that cannot hold their work, a device sighting, a presence change,
// a finding, are retried here a few times before the error is returned.
//
// The budget is short on purpose. busy_timeout already waits five seconds
// inside each attempt, so three attempts are up to fifteen seconds on the
// calling goroutine: long enough to ride out a stall of the usual length,
// short enough that a card which has gone away for a minute is reported
// rather than waited on.

// writeAttempts is how many times a write is tried before its error is
// returned to the caller.
const writeAttempts = 3

// retryBackoff is the pause before each retry, growing by this factor.
var retryBackoff = 100 * time.Millisecond

// retryWrite runs op, retrying when SQLite reports the database busy or
// locked. Any other error is returned at once: a constraint failure or a
// closed database will not improve with waiting.
func (s *Store) retryWrite(ctx context.Context, what string, op func() error) error {
	var err error
	wait := retryBackoff
	for attempt := 1; attempt <= writeAttempts; attempt++ {
		err = op()
		if err == nil {
			if attempt > 1 {
				slog.Debug("write succeeded after retry", "op", what, "attempt", attempt)
			}
			return nil
		}
		if !isBusy(err) || attempt == writeAttempts {
			s.NoteErr(what, err)
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		wait *= 2
	}
	return err
}

// isBusy reports whether err is SQLite saying the database is busy or locked:
// SQLITE_BUSY (5), SQLITE_LOCKED (6) and their extended forms, of which
// SQLITE_BUSY_SNAPSHOT (517) is the one that matters here.
//
// The driver wraps these in its own error type, which is checked first. The
// text is checked as well because an error that has passed through fmt.Errorf
// with %w is still unwrapped by errors.As, but one that was formatted with %v
// somewhere along the way is not, and a retry missed for that reason would be
// a silent regression.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 5, 6:
			return true
		}
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "SQLITE_BUSY")
}
