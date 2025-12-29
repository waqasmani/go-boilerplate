package observability

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

func TestLogger(t *testing.T) {
	// 1. JSON Logger (Default)
	logger, err := NewLogger("info", "json")
	assert.NoError(t, err)
	assert.NotNil(t, logger)

	// 2. Console Logger
	consoleLogger, err := NewLogger("debug", "console")
	assert.NoError(t, err)
	assert.NotNil(t, consoleLogger)

	// 3. Invalid Level Fallback
	badLevelLogger, err := NewLogger("invalid_level", "json")
	assert.NoError(t, err)
	assert.NotNil(t, badLevelLogger)

	// 4. Test Context Fields (Safe to run, checking for no panic)
	ctx := context.WithValue(context.Background(), RequestIDKey, "req-123")
	ctx = context.WithValue(ctx, UserIDKey, uint64(55))

	// We just ensure these don't panic
	logger.Info(ctx, "test info")
	logger.Error(ctx, "test error")
	_ = logger.Sync()
}

func TestMetrics_DefaultRegistry(t *testing.T) {
	// Use a custom registry for this test to avoid conflicts
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Namespace: "test",
		Subsystem: "unit",
		Registry:  registry,
		Gatherer:  registry,
	}

	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	assert.NotNil(t, m.HttpRequestsTotal)
	assert.NotNil(t, m.HttpRequestDuration)
	assert.NotNil(t, m.DatabaseQuerySuccess)

	// Test recording metrics
	m.HttpRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	m.HttpRequestDuration.WithLabelValues("GET", "/test").Observe(0.5)

	// Verify metrics were recorded
	metricFamilies, err := m.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, metricFamilies)
}

func TestMetrics_MultipleInstances(t *testing.T) {
	// Test that we can create multiple metrics instances with different registries
	registry1 := prometheus.NewRegistry()
	cfg1 := MetricsConfig{
		Namespace: "test1",
		Registry:  registry1,
		Gatherer:  registry1,
	}
	m1 := NewMetricsWithConfig(cfg1)
	defer m1.Unregister()

	registry2 := prometheus.NewRegistry()
	cfg2 := MetricsConfig{
		Namespace: "test2",
		Registry:  registry2,
		Gatherer:  registry2,
	}
	m2 := NewMetricsWithConfig(cfg2)
	defer m2.Unregister()

	// Both should work independently
	m1.HttpRequestsTotal.WithLabelValues("GET", "/test1", "200").Inc()
	m2.HttpRequestsTotal.WithLabelValues("POST", "/test2", "201").Inc()

	// Verify each registry has its own metrics
	families1, err := m1.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families1)

	families2, err := m2.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families2)
}

func TestMetrics_RecordDatabaseStats(t *testing.T) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	// Record some stats
	m.RecordDatabaseStats(25, 10, 15)

	// Verify the gauge was set
	families, err := m.Gatherer().Gather()
	assert.NoError(t, err)

	foundConnectionMetric := false
	for _, family := range families {
		if family.GetName() == "database_connections" {
			foundConnectionMetric = true
			assert.Equal(t, 3, len(family.GetMetric())) // open, in_use, idle
		}
	}
	assert.True(t, foundConnectionMetric, "database_connections metric should be present")
}

func TestMetrics_RecordBackgroundJob(t *testing.T) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	// Test successful job
	m.RecordBackgroundJob("test_job", time.Second, nil)

	// Test failed job
	m.RecordBackgroundJob("test_job", time.Second*2, assert.AnError)

	families, err := m.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families)

	foundDuration := false
	foundErrors := false
	for _, family := range families {
		if family.GetName() == "background_job_duration_seconds" {
			foundDuration = true
		}
		if family.GetName() == "background_job_errors_total" {
			foundErrors = true
		}
	}
	assert.True(t, foundDuration, "background job duration should be recorded")
	assert.True(t, foundErrors, "background job errors should be recorded")
}

func TestMetrics_RecordError(t *testing.T) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	// Test different error types
	m.RecordError(errors.ErrorTypeClient, "GET", "/test")
	m.RecordError(errors.ErrorTypeServer, "POST", "/api")
	m.RecordError(errors.ErrorTypeNetwork, "GET", "/external")

	families, err := m.Gatherer().Gather()
	assert.NoError(t, err)

	errorMetrics := map[string]bool{
		"error_total":         false,
		"client_error_total":  false,
		"server_error_total":  false,
		"network_error_total": false,
	}

	for _, family := range families {
		if _, exists := errorMetrics[family.GetName()]; exists {
			errorMetrics[family.GetName()] = true
		}
	}

	for metric, found := range errorMetrics {
		assert.True(t, found, "%s should be recorded", metric)
	}
}

func TestMetrics_Unregister(t *testing.T) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)

	// Record a metric
	m.HttpRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()

	// Verify it's there
	families, err := m.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families)

	// Unregister
	m.Unregister()

	// Create new instance with same registry - should work without conflicts
	m2 := NewMetricsWithConfig(cfg)
	defer m2.Unregister()

	// Should be able to record metrics
	m2.HttpRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	families2, err := m2.Gatherer().Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families2)
}

func TestMetrics_NilRegistryUnregister(t *testing.T) {
	// Create metrics without registry
	m := &Metrics{
		registry: nil,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		m.Unregister()
	})
}

func TestDefaultMetricsConfig(t *testing.T) {
	cfg := DefaultMetricsConfig()
	assert.Equal(t, "api", cfg.Namespace)
	assert.Equal(t, "", cfg.Subsystem)
	assert.NotNil(t, cfg.Registry)
	assert.NotNil(t, cfg.Gatherer)
}

func TestTracer(t *testing.T) {
	tracer := NewTracer("test-service")
	assert.NotNil(t, tracer)

	ctx, span := tracer.Start(context.Background(), "test-span")
	defer span.End()
	assert.NotNil(t, span)
	assert.NotNil(t, ctx)
}

func TestLogger_Levels(t *testing.T) {
	// Test creating logger with all possible levels to ensure no panics
	levels := []string{"debug", "info", "warn", "error", "dpanic", "panic", "fatal"}

	for _, lvl := range levels {
		l, err := NewLogger(lvl, "json")
		assert.NoError(t, err)
		assert.NotNil(t, l)
	}

	// Test console encoding
	l, err := NewLogger("info", "console")
	assert.NoError(t, err)
	assert.NotNil(t, l)

	// Test sync (often ignored, but good to cover)
	_ = l.Sync()
}

func TestAuditLogger_Event(t *testing.T) {
	l, _ := NewLogger("info", "console")
	audit := NewAuditLogger(l)

	// Just ensure it doesn't panic on execution
	audit.LogSecurityEvent(context.Background(), SecurityEvent{
		Type:    "test",
		Success: true,
	})
}

func TestContextFields_EdgeCases(t *testing.T) {
	l, _ := NewLogger("info", "json")

	// Context with wrong type for keys
	ctx := context.WithValue(context.Background(), RequestIDKey, 12345) // Should be string

	// Should not panic, just ignore the field
	l.Info(ctx, "test")
}

func BenchmarkMetrics_RecordHTTPRequest(b *testing.B) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.HttpRequestsTotal.WithLabelValues("GET", "/api/test", "200").Inc()
		}
	})
}

func BenchmarkMetrics_RecordDuration(b *testing.B) {
	registry := prometheus.NewRegistry()
	cfg := MetricsConfig{
		Registry: registry,
		Gatherer: registry,
	}
	m := NewMetricsWithConfig(cfg)
	defer m.Unregister()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.HttpRequestDuration.WithLabelValues("GET", "/api/test").Observe(0.123)
		}
	})
}
