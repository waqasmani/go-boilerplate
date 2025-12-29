// internal/infrastructure/observability/audit.go
package observability

import (
	"context"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type AuditLogger struct {
	logger      *Logger
	file        *os.File
	mu          sync.Mutex
	isDedicated bool
}
type SecurityEvent struct {
	Type      string
	Action    string
	UserID    uint64
	Resource  string
	Success   bool
	IPAddress string
}

// NewAuditLogger creates an audit logger instance
func NewAuditLogger(logger *Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// NewDedicatedAuditLogger creates an audit logger that writes to a separate file
func NewDedicatedAuditLogger(filePath, format string) (*AuditLogger, error) {
	// Create file if it doesn't exist, append if it does
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}

	// Create zap encoder
	var encoder zapcore.Encoder
	if format == "console" {
		encoderConfig := zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		// SIEM-friendly JSON format
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
		encoderConfig.LevelKey = "level"
		encoderConfig.NameKey = "logger"
		encoderConfig.CallerKey = "caller"
		encoderConfig.MessageKey = "message"
		encoderConfig.StacktraceKey = "stack"
		encoderConfig.LineEnding = zapcore.DefaultLineEnding
		encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
		encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Create core that writes to our file
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(file),
		zapcore.InfoLevel, // Always capture audit events
	)

	// Create the dedicated logger
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	dedicatedLogger := &Logger{zap: zapLogger}

	return &AuditLogger{
		logger:      dedicatedLogger,
		file:        file,
		isDedicated: true,
	}, nil
}

// Close releases any resources held by the audit logger
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.file != nil {
		err := a.file.Close()
		a.file = nil
		return err
	}
	return nil
}

// LogSecurityEvent logs a security-relevant event with structured data
func (a *AuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.logger.Info(ctx, "AUDIT",
		zap.String("event_type", event.Type),
		zap.Uint64("user_id", event.UserID),
		zap.String("action", event.Action),
		zap.String("resource", event.Resource),
		zap.Bool("success", event.Success),
		zap.String("ip_address", event.IPAddress),
		zap.Time("event_time", time.Now().UTC()), // Explicit UTC timestamp for SIEM
		zap.String("audit_version", "1.0"),
	)
}
