package observability

import (
	"context"
	"runtime"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	UserIDKey    contextKey = "user_id"
	TraceIDKey   contextKey = "trace_id"
	SessionIDKey contextKey = "session_id"
)

type Logger struct {
	zap *zap.Logger
}

func NewLogger(level string, encoding string) (*Logger, error) {
	cfg := zap.NewProductionConfig()

	if encoding == "console" {
		cfg.Encoding = "console"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}
	cfg.Level.SetLevel(zapLevel)

	cfg.EncoderConfig.CallerKey = "caller"
	cfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	logger, err := cfg.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, err
	}

	return &Logger{zap: logger}, nil
}

func (l *Logger) Info(ctx context.Context, msg string, fields ...zap.Field) {
	l.zap.Info(msg, append(l.contextFields(ctx), fields...)...)
}

func (l *Logger) Error(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, zap.Stack("stack"))
	l.zap.Error(msg, append(l.contextFields(ctx), fields...)...)
}

func (l *Logger) Warn(ctx context.Context, msg string, fields ...zap.Field) {
	l.zap.Warn(msg, append(l.contextFields(ctx), fields...)...)
}

func (l *Logger) Debug(ctx context.Context, msg string, fields ...zap.Field) {
	l.zap.Debug(msg, append(l.contextFields(ctx), fields...)...)
}

func (l *Logger) Fatal(ctx context.Context, msg string, fields ...zap.Field) {
	l.zap.Fatal(msg, append(l.contextFields(ctx), fields...)...)
}

func (l *Logger) WithContext(ctx context.Context, keysAndValues ...interface{}) context.Context {
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key, ok := keysAndValues[i].(contextKey)
			if ok {
				ctx = context.WithValue(ctx, key, keysAndValues[i+1])
			}
		}
	}
	return ctx
}

func (l *Logger) contextFields(ctx context.Context) []zap.Field {
	fields := make([]zap.Field, 0, 5)

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		fields = append(fields, zap.String("request_id", requestID))
	}

	if userID, ok := ctx.Value(UserIDKey).(uint64); ok {
		fields = append(fields, zap.Uint64("user_id", userID))
	}

	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		fields = append(fields, zap.String("trace_id", traceID))
	}

	if sessionID, ok := ctx.Value(SessionIDKey).(string); ok {
		fields = append(fields, zap.String("session_id", sessionID))
	}

	pc, file, line, ok := runtime.Caller(2)
	if ok {
		funcName := runtime.FuncForPC(pc).Name()
		fields = append(fields, zap.String("caller", funcName))
		fields = append(fields, zap.String("file", file))
		fields = append(fields, zap.Int("line", line))
	}

	return fields
}

func (l *Logger) Sync() error {
	return l.zap.Sync()
}

func (l *Logger) Field(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}