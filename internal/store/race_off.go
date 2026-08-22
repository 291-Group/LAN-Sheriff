//go:build !race

package store

// raceEnabled reports whether this binary was built with the race detector.
//
// It exists so a throughput assertion can tell "the code got slower" apart from
// "the race detector is instrumenting every memory access". The detector costs
// roughly an order of magnitude, and CI runs the whole suite under it.
const raceEnabled = false
