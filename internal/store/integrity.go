package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"modernc.org/sqlite"
)

// **A damaged database is a fault to report, not a condition to live with.**
//
// The soak rig on a Raspberry Pi ran for three days with a malformed
// database. Its SD card had written foreign data over four pages of the
// flows and DNS tables. Writes kept landing on healthy pages, so the ingest
// banner stayed quiet; every suspicion rule, the pruner and the services
// refresh failed on every pass, about sixteen thousand warnings in a log
// nobody opens, and /api/health answered 200 throughout. The Wanted List
// simply stopped growing, which reads as a quiet network.
//
// This is the opposite case to retry.go. A busy database recovers by itself
// and must not be reported as broken; a malformed one never recovers, and
// waiting only hides it. So corruption is latched the first time anything
// sees it, kept for the life of the process, and reported by the health
// endpoint, the health command and the dashboard, with what to do about it.
//
// Two ways in: any background job that gets SQLITE_CORRUPT or SQLITE_NOTADB
// back reports it through NoteErr, and an integrity check runs at start and
// every IntegrityInterval so damage in a table nothing happens to be reading
// is still found.

// IntegrityInterval is how often RunIntegrityChecker reads the whole
// database. quick_check reads every page, so this is a trade between how long
// damage can go unnoticed and how much reading a slow card is asked to do.
const IntegrityInterval = 6 * time.Hour

// Damage describes a database that SQLite has reported as malformed.
type Damage struct {
	// Error is what SQLite said, in English. Shown as-is, like the ingest
	// error: it names a storage fault, not anything the user did.
	Error string `json:"error"`
	// Source is what found it: "integrity check", or the job whose query
	// failed.
	Source string    `json:"source"`
	Since  time.Time `json:"since"`
	// Path is the database file, for the log line and the command line. Never
	// serialised: /api/health answers without a login, and a data path can
	// carry a username.
	Path string `json:"-"`
	// File is the database's file name alone, which is safe to show anyone.
	File string `json:"file"`
}

// damageLatch holds the first damage seen. It is never cleared: SQLite does
// not repair a malformed file, so nothing short of replacing the file (which
// means a restart) can make it go away.
type damageLatch struct {
	mu sync.Mutex
	d  *Damage
}

// Damage reports whether the database has been found malformed, and if so
// when and by what. Nil means no damage has been seen, not that none exists:
// see IntegrityInterval.
func (s *Store) Damage() *Damage {
	s.damage.mu.Lock()
	defer s.damage.mu.Unlock()
	if s.damage.d == nil {
		return nil
	}
	d := *s.damage.d
	return &d
}

// NoteErr records err as database damage if it is one, and does nothing
// otherwise. Safe to call with any error, including nil, from any goroutine.
func (s *Store) NoteErr(source string, err error) {
	if !IsCorrupt(err) {
		return
	}
	s.latchDamage(source, err.Error())
}

func (s *Store) latchDamage(source, msg string) {
	s.damage.mu.Lock()
	first := s.damage.d == nil
	if first {
		s.damage.d = &Damage{Error: msg, Source: source, Since: time.Now(), Path: s.path, File: filepath.Base(s.path)}
	}
	s.damage.mu.Unlock()
	if first {
		// Once, at ERROR, with the remedy. The queries that keep failing will
		// go on logging their own warnings; this is the line that says why.
		slog.Error("the database is damaged; LAN Sheriff cannot read part of what it recorded",
			"found_by", source, "err", msg, "fix", Remedy(s.path))
	}
}

// Remedy is what to do about a damaged database at path, in English, for
// logs and the command line. The dashboard carries its own translated copy.
// Given a bare file name it says "the data directory" rather than a folder.
func Remedy(path string) string {
	dir := filepath.Dir(path)
	if dir == "." {
		dir = "the data directory"
	}
	base := filepath.Base(path)
	return fmt.Sprintf("stop LAN Sheriff, move %s, %s-wal and %s-shm out of %s, then start it again. "+
		"It starts a new database: history, device names and settings begin again, and the moved files are yours to keep or delete. "+
		"Damage like this usually means the storage itself is failing; on an SD card, consider replacing it.",
		base, base, base, dir)
}

// IsCorrupt reports whether err is SQLite saying the database file is
// malformed (SQLITE_CORRUPT, 11) or not a database at all (SQLITE_NOTADB,
// 26), including their extended forms.
//
// The text is checked as well as the driver's error type for the same reason
// isBusy does: an error formatted with %v on its way here no longer unwraps.
func IsCorrupt(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 11, 26:
			return true
		}
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database disk image is malformed") ||
		strings.Contains(msg, "file is not a database") ||
		strings.Contains(msg, "SQLITE_CORRUPT") ||
		strings.Contains(msg, "SQLITE_NOTADB")
}

// CheckIntegrity runs SQLite's quick_check over the whole database and
// latches any damage it finds. It returns the damage, or nil if the check
// passed. An error is returned only when the check itself could not run for
// a reason other than damage (a cancelled context, a closed database).
//
// quick_check rather than integrity_check: it finds damaged pages and
// malformed records, which is what a failing card produces, without
// cross-checking every index against its table, which on a router's database
// is the difference between seconds and minutes of reading.
func (s *Store) CheckIntegrity(ctx context.Context) (*Damage, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA quick_check(1)`)
	if err != nil {
		if IsCorrupt(err) {
			s.latchDamage("integrity check", err.Error())
			return s.Damage(), nil
		}
		return nil, err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line sql.NullString
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		if line.Valid && line.String != "ok" {
			problems = append(problems, line.String)
		}
	}
	if err := rows.Err(); err != nil {
		if IsCorrupt(err) {
			s.latchDamage("integrity check", err.Error())
			return s.Damage(), nil
		}
		return nil, err
	}
	if len(problems) > 0 {
		s.latchDamage("integrity check", strings.Join(problems, "; "))
		return s.Damage(), nil
	}
	return nil, nil
}

// RunIntegrityChecker checks the database once shortly after start and then
// every interval, until ctx is cancelled or damage is found. Once damage is
// latched there is nothing more for it to learn.
//
// The first check waits a minute so it does not compete with startup's own
// reads on slow storage.
func (s *Store) RunIntegrityChecker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = IntegrityInterval
	}
	wait := time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = interval
		start := time.Now()
		d, err := s.CheckIntegrity(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil && !isBusy(err) {
				slog.Warn("integrity check could not run", "err", err)
			}
		case d != nil:
			return
		default:
			slog.Debug("integrity check passed", "took", time.Since(start).Round(time.Millisecond))
		}
	}
}
