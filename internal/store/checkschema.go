package store

import (
	"fmt"
	"strings"
)

// checkSchema verifies that the database actually has the shape the code writes
// against, and refuses to open it if not.
//
// The failure this prevents: a migration edited in place rather than appended
// to leaves an already-migrated database on an older column layout, and the
// code then writes against columns that are not there. Every flow write fails
// and the application carries on, because writes to other tables still succeed
// and the dashboard still serves. The only trace is a line in a log.
//
// A mismatch here is a programming error, not a user error, and the right
// response is to fail immediately and loudly rather than to run in a state where
// some data is silently discarded. Starting up is the last moment at which this
// can be reported clearly.
func (s *Store) checkSchema() error {
	// Only the columns the write paths depend on. Read paths degrade visibly;
	// a missing write column loses data quietly, which is the case that matters.
	required := map[string][]string{
		"flows":       {"flow_hash", "ts_start", "ts_last", "direction", "device_id"},
		"endpoints":   {"ip", "first_seen", "last_seen", "enriched_at"},
		"dns_events":  {"ts", "qname", "device_id"},
		"devices":     {"id", "mac", "name", "model", "mac_randomized"},
		"device_keys": {"key", "device_id", "kind"},
		// The Dispatch tables are checked even though the feature is off by
		// default. They are written by a network peer, and a write path that
		// fails silently is precisely the failure this function exists for,
		// being unused most of the time makes that *more* likely to go
		// unnoticed, not less.
		"peers":          {"peer_id", "public_key", "trust", "paired_at"},
		"peer_summaries": {"peer_id", "device", "hour", "flows", "received_at"},
	}

	var problems []string
	for table, columns := range required {
		have, err := s.columns(table)
		if err != nil {
			return fmt.Errorf("inspect table %q: %w", table, err)
		}
		if len(have) == 0 {
			problems = append(problems, fmt.Sprintf("table %q is missing entirely", table))
			continue
		}
		for _, c := range columns {
			if !have[c] {
				problems = append(problems, fmt.Sprintf("%s.%s is missing", table, c))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf(
			"the database at %s does not match this build (%s).\n"+
				"This means a migration did not apply. Moving the file aside will start a clean "+
				"database; the old one can be kept for reference",
			s.path, strings.Join(problems, "; "))
	}
	return nil
}

func (s *Store) columns(table string) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}
