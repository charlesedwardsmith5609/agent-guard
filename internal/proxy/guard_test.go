package proxy

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"agent-guard/internal/policy"
)

func TestGuardFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		d        decFunc
		wantRule string
		want     policy.Verdict
	}{
		{"allow", func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
			return policy.Decision{Verdict: policy.Allow, Rule: "x"}, nil
		}, "x", policy.Allow},
		{"error", func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
			return policy.Decision{Verdict: policy.Allow}, fmt.Errorf("x")
		}, "fail-closed:error", policy.Block},
		{"panic", func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
			panic("boom")
		}, "fail-closed:error", policy.Block},
		{"unknown verdict", func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
			return policy.Decision{Verdict: "MAYBE"}, nil
		}, "fail-closed:verdict", policy.Block},
		{"empty verdict", func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
			return policy.Decision{}, nil
		}, "fail-closed:verdict", policy.Block},
		{"timeout", func(ctx context.Context, _ policy.Context, _ policy.ToolCall) (policy.Decision, error) {
			<-ctx.Done()
			return policy.Decision{Verdict: policy.Allow}, nil
		}, "fail-closed:timeout", policy.Block},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuard(tc.d, 50*time.Millisecond, 4)
			got := g.decide(context.Background(), policy.Context{}, policy.ToolCall{Name: "t"})
			if got.Verdict != tc.want || got.Rule != tc.wantRule {
				t.Errorf("got %+v, want %s/%s", got, tc.want, tc.wantRule)
			}
		})
	}
}

// decideAsync runs g.decide off the test goroutine so a regression fails by timeout, not a hang.
func decideAsync(t *testing.T, g *guard) policy.Decision {
	t.Helper()
	ch := make(chan policy.Decision, 1)
	go func() { ch <- g.decide(context.Background(), policy.Context{}, policy.ToolCall{}) }()
	return recv(t, ch)
}

// A result that is ready at the same time as a cancelled context must not be honoured.
func TestGuardIgnoresResultAfterCancellation(t *testing.T) {
	g := newGuard(decFunc(func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
		return policy.Decision{Verdict: policy.Allow, Rule: "x"}, nil
	}), time.Second, 1024) // slots free asynchronously; leave room for every iteration
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 200; i++ { // both select cases can be ready; every outcome must be BLOCK
		ch := make(chan policy.Decision, 1)
		go func() { ch <- g.decide(ctx, policy.Context{}, policy.ToolCall{}) }()
		if d := recv(t, ch); d.Verdict != policy.Block || d.Rule != "fail-closed:timeout" {
			t.Fatalf("iteration %d: got %+v", i, d)
		}
	}
}

func TestGuardDeciderGoroutineExitsAfterTimeout(t *testing.T) {
	exited := make(chan struct{})
	g := newGuard(decFunc(func(ctx context.Context, _ policy.Context, _ policy.ToolCall) (policy.Decision, error) {
		defer close(exited)
		<-ctx.Done()
		return policy.Decision{}, ctx.Err()
	}), 20*time.Millisecond, 1)
	if d := decideAsync(t, g); d.Verdict != policy.Block {
		t.Fatalf("got %+v", d)
	}
	recv(t, exited)
}

// A decider that ignores ctx holds its slot; the guard must bound goroutines and fail closed.
func TestGuardOverload(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	g := newGuard(decFunc(func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
		started <- struct{}{}
		<-release
		return policy.Decision{Verdict: policy.Allow}, nil
	}), 20*time.Millisecond, 1)
	t.Cleanup(func() { close(release) })

	if d := decideAsync(t, g); d.Rule != "fail-closed:timeout" {
		t.Fatalf("first call: %+v", d)
	}
	recv(t, started)
	if d := decideAsync(t, g); d.Rule != "fail-closed:overloaded" || d.Verdict != policy.Block {
		t.Fatalf("second call: %+v", d)
	}
}

// Many concurrent callers share one guard and a Decider that owns its state with a mutex.
func TestGuardConcurrent(t *testing.T) {
	var mu sync.Mutex
	count := 0
	g := newGuard(decFunc(func(context.Context, policy.Context, policy.ToolCall) (policy.Decision, error) {
		mu.Lock()
		count++
		mu.Unlock()
		return policy.Decision{Verdict: policy.Allow, Rule: "ok"}, nil
	}), time.Second, 256)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := g.decide(context.Background(), policy.Context{}, policy.ToolCall{}); d.Verdict != policy.Allow {
				t.Errorf("got %+v", d)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	recv(t, done)
	mu.Lock()
	defer mu.Unlock()
	if count != 100 {
		t.Errorf("count = %d", count)
	}
}
