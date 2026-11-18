package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The error the Pi soak rig logged sixteen thousand times, word for word.
var errCorruptText = errors.New("first contact query: database disk image is malformed (11)")

func TestIsCorrupt(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errCorruptText, true},
		{fmt.Errorf("rule rare_destination: %w", errCorruptText), true},
		{errors.New("file is not a database (26)"), true},
		// Busy is the other kind of storage error, and must never be mistaken
		// for damage: it recovers by itself.
		{errBusyText, false},
		{errors.New("UNIQUE constraint failed: devices.mac"), false},
		{context.Canceled, false},
	}
	for _, c := range cases {
		if got := IsCorrupt(c.err); got != c.want {
			t.Errorf("IsCorrupt(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// NoteErr keeps the first damage it is told about and ignores everything
// that is not damage.
func TestNoteErrLatchesFirstDamageOnly(t *testing.T) {
	s := newTestStore(t)
	s.NoteErr("prune", errBusyText)
	s.NoteErr("prune", nil)
	if d := s.Damage(); d != nil {
		t.Fatalf("busy and nil errors latched damage: %+v", d)
	}
	s.NoteErr("suspicion rules", errCorruptText)
	s.NoteErr("prune", errors.New("database disk image is malformed (11)"))
	d := s.Damage()
	if d == nil {
		t.Fatal("corrupt error did not latch")
	}
	if d.Source != "suspicion rules" || d.Error != errCorruptText.Error() {
		t.Errorf("latched %+v, want the first report kept", d)
	}
	if d.File != "test.db" || d.Path == "" {
		t.Errorf("damage file %q path %q", d.File, d.Path)
	}
}

func TestCheckIntegrityPassesOnHealthyDatabase(t *testing.T) {
	s := newTestStore(t)
	d, err := s.CheckIntegrity(context.Background())
	if err != nil || d != nil {
		t.Fatalf("healthy database: damage %+v err %v", d, err)
	}
	if s.Damage() != nil {
		t.Error("healthy check latched damage")
	}
}

// The real thing: a database whose file has had a page overwritten, the way
// the soak rig's SD card overwrote four. The schema is untouched, so the
// store opens normally, which is exactly why nothing noticed.
func TestCheckIntegrityFindsADamagedPage(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sheriff.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE filler (id INTEGER PRIMARY KEY, blob BLOB)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO filler (blob) VALUES (randomblob(1000))`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	var pageSize int
	if err := s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	// The filler table's root page: overwriting a b-tree page with the
	// all-ones pattern one of the soak rig's pages held.
	var root int
	if err := s.db.QueryRowContext(ctx,
		`SELECT rootpage FROM sqlite_master WHERE name = 'filler'`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	s.Close()

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	junk := []byte(strings.Repeat("\xff", pageSize))
	if _, err := f.WriteAt(junk, int64(root-1)*int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("a database with one damaged data page should still open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	d, err := s.CheckIntegrity(ctx)
	if err != nil {
		t.Fatalf("CheckIntegrity: %v", err)
	}
	if d == nil {
		t.Fatal("damaged page not found")
	}
	if d.Source != "integrity check" || d.Error == "" {
		t.Errorf("damage %+v", d)
	}
	if s.Damage() == nil {
		t.Error("damage found but not latched")
	}
	// And the ordinary query path sees it too, which is how NoteErr hears.
	var n int
	err = s.db.QueryRowContext(ctx, `SELECT count(blob) FROM filler`).Scan(&n)
	if !IsCorrupt(err) {
		t.Errorf("reading the damaged table: err %v, want a corruption error", err)
	}
}

func TestRemedyNamesTheFiles(t *testing.T) {
	r := Remedy(filepath.Join("data", "sheriff.db"))
	for _, want := range []string{"sheriff.db,", "sheriff.db-wal", "sheriff.db-shm", "data"} {
		if !strings.Contains(r, want) {
			t.Errorf("remedy %q lacks %q", r, want)
		}
	}
	if r := Remedy("sheriff.db"); !strings.Contains(r, "the data directory") {
		t.Errorf("bare file name: %q", r)
	}
}
