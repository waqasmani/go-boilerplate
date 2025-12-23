package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

type Tracer struct {
	tracer trace.Tracer
}

func NewTracer(serviceName string) *Tracer {
	return &Tracer{
		tracer: otel.Tracer(serviceName),
	}
}

func (t *Tracer) Start(ctx context.Context, spanName string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, spanName)
}