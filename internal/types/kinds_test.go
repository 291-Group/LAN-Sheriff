package types

import "testing"

// A const block repeats the previous expression when a value is omitted, so an
// omitted value here silently aliases another kind. That happened once.
func TestEventKindsAreDistinct(t *testing.T) {
	kinds := map[EventKind]string{}
	for name, k := range map[string]EventKind{
		"KindConnSnapshot": KindConnSnapshot,
		"KindConnDelta":    KindConnDelta,
		"KindDNS":          KindDNS,
		"KindSighting":     KindSighting,
		"KindDevice":       KindDevice,
	} {
		if k == "" {
			t.Errorf("%s has no value", name)
		}
		if other, clash := kinds[k]; clash {
			t.Errorf("%s and %s are both %q", name, other, k)
		}
		kinds[k] = name
	}
}
