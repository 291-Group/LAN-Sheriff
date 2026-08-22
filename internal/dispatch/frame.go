package dispatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Framing for the Dispatch wire protocol: a 32-bit big-endian length followed by
// that many bytes of JSON. See docs/DISPATCH-PROTOCOL.md §6.
//
// This is the only parser in LAN Sheriff that reads bytes an unknown machine put
// on a socket, so it is written defensively and fuzzed. The specific mistake it
// is written against is the one every framed protocol makes at least once:
// trusting a declared length enough to allocate it.

// MaxFrameSize caps a single frame at 1 MiB.
//
// Generous for the messages that exist, a full summary at the 5,000-bucket
// ceiling is well under this, and small enough that a peer cannot make us
// allocate meaningfully by asking.
const MaxFrameSize = 1 << 20

// frameHeaderLen is the size of the length prefix.
const frameHeaderLen = 4

var (
	// ErrFrameTooLarge is returned for a declared length above MaxFrameSize.
	// The connection must be closed: a peer that sends one is either broken or
	// hostile, and there is no way to resynchronize a stream framed by lengths
	// once one of them is wrong.
	ErrFrameTooLarge = errors.New("dispatch: frame exceeds the maximum size")

	// ErrFrameEmpty is returned for a zero-length frame, which carries no
	// message and would otherwise be a free way to keep a connection alive.
	ErrFrameEmpty = errors.New("dispatch: zero-length frame")
)

// WriteFrame writes one length-prefixed frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrFrameEmpty
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	// One write rather than two, so a frame cannot be torn across a slow link
	// with a header committed and a body that never arrives.
	buf := make([]byte, frameHeaderLen+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[frameHeaderLen:], payload)

	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame.
//
// **The length is validated before anything is allocated.** A peer declaring
// four gigabytes gets an error, not four gigabytes of address space. This is the
// single most important line in the package.
func ReadFrame(r io.Reader) ([]byte, error) {
	var header [frameHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])

	if n == 0 {
		return nil, ErrFrameEmpty
	}
	if n > MaxFrameSize {
		return nil, fmt.Errorf("%w: peer declared %d bytes, limit is %d",
			ErrFrameTooLarge, n, MaxFrameSize)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		// A truncated body is a broken or hostile peer either way; io.EOF here
		// is misleading to a caller, so it is reported as unexpected.
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}
