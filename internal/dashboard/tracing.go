package dashboard

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope for dashboard spans.
const tracerName = "github.com/kubeguard/kubeguard/internal/dashboard"

// tracer returns the globally-configured tracer. When OpenTelemetry is not wired
// (the default), this is a no-op tracer — spans cost nothing and nothing is
// exported. Squad-P3 ships the seam; `InitTracing` (or a test SpanRecorder)
// activates real spans. This keeps traces end-to-end capable without forcing a
// collector dependency at runtime.
func tracer() trace.Tracer { return otel.Tracer(tracerName) }

// startSpan begins a span for an operation; the returned end func closes it.
func startSpan(ctx context.Context, name string, attrs ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tracer().Start(ctx, name, attrs...)
}

// InitTracing wires an OTLP/HTTP trace exporter and installs it as the global
// tracer provider. DEFAULT OFF — the CLI calls this only when an OTLP endpoint
// is configured (`--otel-endpoint` / OTEL_EXPORTER_OTLP_ENDPOINT). No collector
// is contacted otherwise. Returns a shutdown func to flush spans on exit.
func InitTracing(ctx context.Context, endpoint string) (func(context.Context) error, error) {
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName("kubeguard-dashboard")))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
