package telemetry

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"agent-guard/internal/policy"
)

func event() policy.Event {
	start := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	return policy.Event{
		Call:     policy.ToolCall{ID: "toolu_1", Name: "Bash", Input: []byte(`{"command":"cat SECRET-ARG"}`)},
		Decision: policy.Decision{Verdict: policy.Ask, Rule: "sensitive:dotenv", Reason: `sensitive path "SECRET-REASON"`},
		Start:    start, End: start.Add(2500 * time.Microsecond), Stream: true,
	}
}

func TestOneSpanPerDecision(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	o := NewObserver(tp)
	e := event()
	if err := o.Observe(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans", len(spans))
	}
	s := spans[0]
	if s.Name != SpanName {
		t.Errorf("name = %q", s.Name)
	}
	if !s.StartTime.Equal(e.Start) || !s.EndTime.Equal(e.End) {
		t.Errorf("span times %v..%v, want %v..%v", s.StartTime, s.EndTime, e.Start, e.End)
	}
	got := map[string]attribute.Value{}
	for _, kv := range s.Attributes {
		got[string(kv.Key)] = kv.Value
	}
	want := map[string]any{
		"agent_guard.decision": "ASK", "agent_guard.rule": "sensitive:dotenv", "agent_guard.tool": "Bash",
		"agent_guard.tool_use_id": "toolu_1", "agent_guard.latency_ms": 2.5, "agent_guard.stream": true,
	}
	if len(got) != len(want) {
		t.Errorf("attributes = %v", got)
	}
	for k, w := range want {
		if v, ok := got[k]; !ok || v.AsInterface() != w {
			t.Errorf("%s = %v, want %v", k, v.AsInterface(), w)
		}
	}
	for k, v := range got {
		if s := v.Emit(); strings.Contains(s, "SECRET") {
			t.Errorf("attribute %s leaks argument or reason text: %s", k, s)
		}
	}
}

func TestCredentialShapedIDsAreRedacted(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	o := NewObserver(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	e := event()
	e.Call.Name = "sk" + "-" + "abcdefghijklmnopqrstuvwxyz"
	e.Call.ID = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	o.Observe(context.Background(), e)
	for _, kv := range exp.GetSpans()[0].Attributes {
		if v := kv.Value.Emit(); strings.Contains(v, "abcdefghijklmnop") {
			t.Errorf("attribute %s leaks a credential-shaped value: %s", kv.Key, v)
		}
	}
}

func TestToolNameIsSanitised(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	o := NewObserver(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	e := event()
	e.Call.Name = "bad\nname\x1b[0m"
	o.Observe(context.Background(), e)
	for _, kv := range exp.GetSpans()[0].Attributes {
		if kv.Key == "agent_guard.tool" && strings.ContainsAny(kv.Value.AsString(), "\n\x1b") {
			t.Errorf("unsanitised tool name %q", kv.Value.AsString())
		}
	}
}

func TestSetup(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		tp, shutdown, err := Setup("none", nil)
		if err != nil {
			t.Fatal(err)
		}
		NewObserver(tp).Observe(context.Background(), event()) // must not panic
		if err := shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("stdout flushes on shutdown", func(t *testing.T) {
		var buf bytes.Buffer
		tp, shutdown, err := Setup("stdout", &buf)
		if err != nil {
			t.Fatal(err)
		}
		NewObserver(tp).Observe(context.Background(), event())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if !strings.Contains(out, SpanName) || !strings.Contains(out, "agent_guard.decision") {
			t.Errorf("exporter output missing the span: %s", out)
		}
		if strings.Contains(out, "SECRET") {
			t.Errorf("exporter output leaks arguments: %s", out)
		}
	})
	t.Run("stdout without a writer is rejected", func(t *testing.T) {
		if _, _, err := Setup("stdout", nil); err == nil {
			t.Fatal("a nil writer would panic the exporter later; expected an error now")
		}
	})
	t.Run("unknown mode", func(t *testing.T) {
		if _, _, err := Setup("otlp", nil); err == nil {
			t.Fatal("expected an error")
		}
	})
}
