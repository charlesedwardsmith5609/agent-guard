package proxy

import (
	"context"
	"fmt"
	"time"

	"agent-guard/internal/policy"
)

// guard wraps a Decider so that every outcome is a verdict: errors, panics, timeouts, unknown
// verdicts and overload all become BLOCK.
//
// Ownership: the fields are immutable after construction. The sem channel is the only shared
// mutable object; a slot is held from before the Decider goroutine starts until Decide returns.
type guard struct {
	d       policy.Decider
	timeout time.Duration
	sem     chan struct{}
}

func newGuard(d policy.Decider, timeout time.Duration, maxInflight int) *guard {
	return &guard{d: d, timeout: timeout, sem: make(chan struct{}, maxInflight)}
}

func failClosed(rule, reason string) policy.Decision {
	return policy.Decision{Verdict: policy.Block, Rule: rule, Reason: reason}
}

type decideResult struct {
	dec policy.Decision
	err error
}

func (g *guard) decide(ctx context.Context, pc policy.Context, tc policy.ToolCall) policy.Decision {
	select {
	case g.sem <- struct{}{}:
	default:
		return failClosed("fail-closed:overloaded", "too many decisions in flight")
	}
	dctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	res := make(chan decideResult, 1) // buffered: the goroutine never blocks on send
	go func() {
		defer func() { <-g.sem }()
		defer func() {
			if r := recover(); r != nil {
				res <- decideResult{err: fmt.Errorf("decider panic: %v", r)}
			}
		}()
		d, err := g.d.Decide(dctx, pc, tc)
		res <- decideResult{dec: d, err: err}
	}()

	select {
	case r := <-res:
		if dctx.Err() != nil { // a result that raced the deadline or a cancellation does not count
			return failClosed("fail-closed:timeout", "decision timed out")
		}
		if r.err != nil {
			return failClosed("fail-closed:error", "decider error")
		}
		if !r.dec.Verdict.Valid() {
			return failClosed("fail-closed:verdict", "unknown verdict")
		}
		return r.dec
	case <-dctx.Done():
		return failClosed("fail-closed:timeout", "decision timed out")
	}
}
