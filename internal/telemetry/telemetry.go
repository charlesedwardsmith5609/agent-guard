// Package telemetry emits one OpenTelemetry span per tool-call decision.
package telemetry

import (
	"context"
	"fmt"
	"io"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"agent-guard/internal/audit"
	"agent-guard/internal/policy"
)

const tracerName = "agent-guard"

// SpanName is the name of every decision span.
const SpanName = "agent_guard.decide"

// Observer implements policy.Observer. It holds only a Tracer, which is safe for concurrent use.
type Observer struct{ tracer trace.Tracer }

// NewObserver builds an Observer on the given provider.
func NewObserver(tp trace.TracerProvider) *Observer {
	return &Observer{tracer: tp.Tracer(tracerName)}
}

// Observe records the decision as a span backdated to the decision's start. Arguments and the
// reason text (which can contain values) are never attached.
func (o *Observer) Observe(ctx context.Context, e policy.Event) error {
	_, span := o.tracer.Start(ctx, SpanName,
		trace.WithTimestamp(e.Start),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("agent_guard.decision", string(e.Decision.Verdict)),
			attribute.String("agent_guard.rule", audit.RedactID(e.Decision.Rule)),
			attribute.String("agent_guard.tool", audit.RedactID(e.Call.Name)),
			attribute.String("agent_guard.tool_use_id", audit.RedactID(e.Call.ID)),
			attribute.Float64("agent_guard.latency_ms", float64(e.End.Sub(e.Start).Microseconds())/1000),
			attribute.Bool("agent_guard.stream", e.Stream),
		))
	span.End(trace.WithTimestamp(e.End))
	return nil
}

// Setup returns a provider for the given mode and a shutdown function that flushes it.
// "none" is the no-op provider; "stdout" writes spans as JSON to w through a bounded batch
// processor (it drops spans when full rather than blocking a request).
func Setup(mode string, w io.Writer) (trace.TracerProvider, func(context.Context) error, error) {
	switch mode {
	case "", "none":
		return noop.NewTracerProvider(), func(context.Context) error { return nil }, nil
	case "stdout":
		if w == nil {
			return nil, nil, fmt.Errorf("telemetry: stdout mode needs a writer")
		}
		exp, err := stdouttrace.New(stdouttrace.WithWriter(w))
		if err != nil {
			return nil, nil, err
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp, sdktrace.WithMaxQueueSize(2048)),
			sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "agent-guard"))),
		)
		return tp, tp.Shutdown, nil
	}
	return nil, nil, fmt.Errorf("telemetry: unknown mode %q (want none or stdout)", mode)
}
