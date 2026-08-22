package dispatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("x"),
		[]byte(`{"v":1,"type":"ping"}`),
		bytes.Repeat([]byte("a"), 4096),
		bytes.Repeat([]byte("z"), MaxFrameSize),
	}
	for _, payload := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, payload); err != nil {
			t.Fatalf("writing %d bytes: %v", len(payload), err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("reading %d bytes: %v", len(payload), err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip altered a %d-byte payload", len(payload))
		}
	}
}

// The line the whole file exists for: a declared length must be rejected before
// it is used to size anything.
func TestOversizedLengthIsRejectedWithoutAllocating(t *testing.T) {
	// Just under four gigabytes declared, one byte supplied. A reader that
	// trusted the length would try to allocate before discovering the body is
	// not there.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], ^uint32(0))
	r := io.MultiReader(bytes.NewReader(header[:]), strings.NewReader("x"))

	_, err := ReadFrame(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v, want ErrFrameTooLarge", err)
	}
}

func TestFrameSizeBoundary(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, bytes.Repeat([]byte("a"), MaxFrameSize)); err != nil {
			t.Fatalf("a frame exactly at the limit was refused: %v", err)
		}
	})
	t.Run("one over is refused", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteFrame(&buf, bytes.Repeat([]byte("a"), MaxFrameSize+1))
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("error = %v, want ErrFrameTooLarge", err)
		}
	})
	t.Run("reader refuses one over", func(t *testing.T) {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
		_, err := ReadFrame(bytes.NewReader(header[:]))
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("error = %v, want ErrFrameTooLarge", err)
		}
	})
}

// A zero-length frame carries nothing and would be a free keep-alive.
func TestZeroLengthFrameRejected(t *testing.T) {
	var header [4]byte
	if _, err := ReadFrame(bytes.NewReader(header[:])); !errors.Is(err, ErrFrameEmpty) {
		t.Errorf("read error = %v, want ErrFrameEmpty", err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, nil); !errors.Is(err, ErrFrameEmpty) {
		t.Errorf("write error = %v, want ErrFrameEmpty", err)
	}
}

// A peer that dies mid-frame must produce a clear error, not a short payload
// that the caller then parses as if it were complete.
func TestTruncatedFrameIsAnError(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("a complete message")); err != nil {
		t.Fatal(err)
	}
	truncated := buf.Bytes()[:buf.Len()-4]

	_, err := ReadFrame(bytes.NewReader(truncated))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want io.ErrUnexpectedEOF", err)
	}
}

// A header that never completes is EOF, which is how a closed connection is
// distinguished from a corrupt one.
func TestTruncatedHeaderIsEOF(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0, 0}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("error on a cleanly closed stream = %v, want io.EOF", err)
	}
}

// Frames must not bleed into one another.
func TestConsecutiveFrames(t *testing.T) {
	var buf bytes.Buffer
	want := []string{"first", "second", "third"}
	for _, s := range want {
		if err := WriteFrame(&buf, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range want {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != s {
			t.Errorf("got %q, want %q", got, s)
		}
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF after the last frame, got %v", err)
	}
}

// FuzzReadFrame throws arbitrary bytes at the decoder. It must return an error
// or a payload; it must never panic and never allocate on an unvalidated
// length. This is the only parser in the product fed by an unknown machine.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'x'})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255, 'x'})
	f.Add([]byte(`{"v":1}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(got) == 0 {
			t.Fatal("a successful read returned an empty payload")
		}
		if len(got) > MaxFrameSize {
			t.Fatalf("a successful read returned %d bytes, over the limit", len(got))
		}
	})
}
