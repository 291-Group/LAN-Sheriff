package suspicion

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Sink is where findings go. The store implements it.
type Sink interface {
	// RecordObservations writes a rule's findings, updating rather than
	// duplicating anything it has raised before.
	RecordObservations(ctx context.Context, rule string, weight float64, obs []Observation) error
}

// Engine runs the rules.
type Engine struct {
	Rules []Rule
	Sink  Sink
	DB    Queryer

	// Window is how far back each pass looks. Longer than the interval between
	// passes, so a slow pass cannot leave a gap in what was examined.
	Window time.Duration
}

// DefaultWindow is the period each pass examines.
const DefaultWindow = 2 * time.Hour

// DefaultInterval is how often the rules run.
//
// Comfortably shorter than the window, so overlapping coverage is guaranteed
// and nothing falls between two passes. Rules deduplicate their own findings, so
// seeing the same behaviour twice costs nothing.
const DefaultInterval = 5 * time.Minute

// Run evaluates every rule once.
//
// A rule that fails is logged and skipped. One broken rule must not stop the
// others: the engine's job is to notice things, and noticing fewer of them is
// better than noticing none.
func (e *Engine) Run(ctx context.Context, now time.Time, baseline time.Duration) error {
	in := Input{DB: e.DB, Now: now, Window: e.window(), Baseline: baseline}

	var firstErr error
	for _, rule := range e.Rules {
		obs, err := rule.Evaluate(ctx, in)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("suspicion rule failed", "rule", rule.Code(), "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("rule %s: %w", rule.Code(), err)
			}
			continue
		}
		if len(obs) == 0 {
			continue
		}
		if err := e.Sink.RecordObservations(ctx, rule.Code(), rule.Weight(), obs); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("could not record findings", "rule", rule.Code(), "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (e *Engine) window() time.Duration {
	if e.Window > 0 {
		return e.Window
	}
	return DefaultWindow
}

// RunPeriodically evaluates the rules until ctx is cancelled.
//
// baselineAt reports when this install began observing, so rules that reason
// about what is normal here can stay silent until there is enough history to
// have an opinion.
func (e *Engine) RunPeriodically(ctx context.Context, every time.Duration, baselineAt func() time.Time) {
	if every <= 0 {
		every = DefaultInterval
	}
	run := func() {
		base := time.Since(baselineAt())
		if err := e.Run(ctx, time.Now(), base); err != nil && ctx.Err() == nil {
			slog.Debug("suspicion pass had errors", "err", err)
		}
	}
	run()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
