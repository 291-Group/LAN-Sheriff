//go:build race

package store

// raceEnabled reports whether this binary was built with the race detector.
// See race_off.go.
const raceEnabled = true
