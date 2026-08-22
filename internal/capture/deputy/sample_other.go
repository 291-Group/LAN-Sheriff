//go:build !linux && !darwin && !windows

package deputy

import (
	"fmt"
	"runtime"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// No socket-table backend for this platform. Linux, macOS and Windows each have
// a real implementation; this covers everything else (BSD, Solaris, and any
// future target).
//
// The stub exists so the binary still builds and runs everywhere: the app comes
// up, reports Deputy Mode unavailable with an explanation, and serves whatever
// other sources it has. Capture availability must never stop the app starting.

type unsupportedSampler struct{}

func newSampler() (sampler, error) {
	return nil, fmt.Errorf("Deputy Mode does not support %s yet", runtime.GOOS)
}

func (unsupportedSampler) sample() ([]types.Conn, error) { return nil, nil }
func (unsupportedSampler) byteCounts() bool              { return false }
func (unsupportedSampler) close() error                  { return nil }
