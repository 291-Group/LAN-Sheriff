package suspicion

import (
	"context"
	"errors"
	"testing"
	"time"
)

type brokenRule struct{ err error }

func (brokenRule) Code() string    { return "broken" }
func (brokenRule) Weight() float64 { return 1 }
func (r brokenRule) Evaluate(context.Context, Input) ([]Observation, error) {
	return nil, r.err
}

// A failing pass reaches OnPassError with the rule's own error still
// unwrappable, which is how the store tells damage from anything else.
func TestRunPeriodicallyReportsPassErrors(t *testing.T) {
	cause := errors.New("database disk image is malformed (11)")
	got := make(chan error, 1)
	e := &Engine{
		Rules:       []Rule{brokenRule{err: cause}},
		OnPassError: func(err error) { got <- err },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.RunPeriodically(ctx, time.Hour, func() time.Time { return time.Now() })

	select {
	case err := <-got:
		if !errors.Is(err, cause) {
			t.Errorf("OnPassError got %v, which does not wrap the rule's error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnPassError was not called after a failing pass")
	}
}
