package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// The error the first router install logged, word for word, from a card that
// stalled under sustained writes. It is what retryWrite exists to absorb.
var errBusyText = errors.New("database is locked (5) (SQLITE_BUSY)")

func TestRetryWriteRetriesBusyAndStops(t *testing.T) {
	s := newTestStore(t)
	saved := retryBackoff
	retryBackoff = time.Millisecond
	t.Cleanup(func() { retryBackoff = saved })

	// Busy twice, then fine: the caller never hears about it.
	calls := 0
	err := s.retryWrite(context.Background(), "test", func() error {
		calls++
		if calls < 3 {
			return errBusyText
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("busy twice then ok: err=%v calls=%d, want nil and 3", err, calls)
	}

	// Busy for longer than the budget: the error comes back, and the budget
	// was spent, not exceeded.
	calls = 0
	err = s.retryWrite(context.Background(), "test", func() error {
		calls++
		return errBusyText
	})
	if !errors.Is(err, errBusyText) || calls != writeAttempts {
		t.Errorf("always busy: err=%v calls=%d, want the busy error after %d attempts", err, calls, writeAttempts)
	}

	// Any other error is returned at once. A constraint failure does not
	// improve with waiting, and retrying it would hide a bug three times over.
	calls = 0
	other := errors.New("UNIQUE constraint failed")
	err = s.retryWrite(context.Background(), "test", func() error {
		calls++
		return other
	})
	if !errors.Is(err, other) || calls != 1 {
		t.Errorf("other error: err=%v calls=%d, want it back after 1 attempt", err, calls)
	}
}

// isBusy must recognise the driver's own error, the extended BUSY_SNAPSHOT
// code, and the text once it has been through fmt.Errorf with %v.
func TestBusyDetection(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// A real one from the driver: a second connection holding the write lock
	// with no busy_timeout to wait it out.
	other, err := sql.Open("sqlite", s.path+"?_pragma=busy_timeout(0)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	tx, err := s.db.BeginTx(ctx, nil) // takes the write lock (immediate)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = other.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES ('x', 'y')`)
	if err == nil {
		t.Fatal("second writer succeeded while the lock was held")
	}
	if !isBusy(err) {
		t.Errorf("driver error %q not recognised as busy", err)
	}

	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errBusyText, true},
		{errors.New("database is locked (517)"), true},
		{errors.New("no such table: nothing"), false},
	} {
		if got := isBusy(c.err); got != c.want {
			t.Errorf("isBusy(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestOpenReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	ctx := context.Background()

	// Nothing to read yet.
	if _, err := OpenReadOnly(path); err == nil {
		t.Error("OpenReadOnly created a database; it must only open one that exists")
	}

	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFlows(ctx, []types.Flow{flow("93.184.216.34", time.Now(), true)}); err != nil {
		t.Fatal(err)
	}

	// While the writer is still open, as the health check sees it.
	r, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly beside a live writer: %v", err)
	}
	defer r.Close()
	if _, err := r.Peers(ctx); err != nil {
		t.Errorf("read through the read-only handle: %v", err)
	}
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil || n != 1 {
		t.Errorf("flows via read-only = %d (%v), want 1", n, err)
	}
	if _, err := r.db.Exec(`INSERT INTO settings (key, value) VALUES ('x', 'y')`); err == nil {
		t.Error("a write through the read-only handle succeeded")
	}
	// And the writer was never blocked by the reader.
	if err := w.WriteFlows(ctx, []types.Flow{flow("93.184.216.35", time.Now(), true)}); err != nil {
		t.Errorf("writer blocked by a read-only reader: %v", err)
	}
	w.Close()

	// After a clean close, with no -wal or -shm left behind.
	r2, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly after close: %v", err)
	}
	defer r2.Close()
	if _, err := r2.PairingHistory(ctx, 5); err != nil {
		t.Errorf("read after close: %v", err)
	}
}

func TestCheckpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 50; i++ {
		if err := s.WriteFlows(ctx, []types.Flow{flow("93.184.216.34", now.Add(time.Duration(i)*time.Second), true)}); err != nil {
			t.Fatal(err)
		}
	}
	frames, done, err := s.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if frames == 0 || done != frames {
		t.Errorf("checkpoint: %d frames in the log, %d written back; want all of a non-empty log", frames, done)
	}
	// A second pass finds the whole log already written back.
	if frames, done, err = s.Checkpoint(ctx); err != nil || done != frames {
		t.Errorf("second checkpoint: frames=%d done=%d err=%v, want done == frames", frames, done, err)
	}
}
