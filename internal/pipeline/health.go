package pipeline

import (
	"sync"
	"time"
)

// Ingest health.
//
// A write that fails is not necessarily visible: the dashboard keeps serving,
// other tables keep updating, and the only trace is a log line. A broken flows
// table can therefore sit frozen while the product looks entirely healthy.
//
// So failures are counted and the last one is kept, where the API can report them
// and the UI can say plainly that observations are not being recorded. Losing
// data quietly is worse than saying so.

// Health is a snapshot of whether observations are actually reaching storage.
type Health struct {
	// Writes and Failures count flush attempts since start.
	Writes   int64 `json:"writes"`
	Failures int64 `json:"failures"`
	// Consecutive is the current run of failures. Anything above zero means data
	// is being dropped right now.
	Consecutive int64 `json:"consecutive_failures"`
	// LastError is the most recent failure, in English. It names a programming
	// or environment fault rather than anything the user did, so it is shown
	// as-is rather than translated.
	LastError string     `json:"last_error,omitempty"`
	LastFail  *time.Time `json:"last_failure,omitempty"`
	LastWrite *time.Time `json:"last_write,omitempty"`
}

// Healthy reports whether observations are currently reaching storage.
func (h Health) Healthy() bool { return h.Consecutive == 0 }

type healthTracker struct {
	mu sync.Mutex
	h  Health
}

func (t *healthTracker) succeeded() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.h.Writes++
	t.h.Consecutive = 0
	t.h.LastWrite = &now
}

func (t *healthTracker) failed(err error) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.h.Failures++
	t.h.Consecutive++
	t.h.LastError = err.Error()
	t.h.LastFail = &now
}

func (t *healthTracker) snapshot() Health {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.h
}
