package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestMetrics(t *testing.T) {
	m := NewMetrics()
	assert.NotNil(t, m.HttpRequestsTotal)
	assert.NotNil(t, m.HttpRequestDuration)
	assert.NotNil(t, m.DatabaseQuerySuccess)
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
