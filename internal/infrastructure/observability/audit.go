package observability

import (
	"context"

	"go.uber.org/zap"
)

type AuditLogger struct {
	logger *Logger
}

type SecurityEvent struct {
	Type      string
	Action    string
	UserID    uint64
	Resource  string
	Success   bool
	IPAddress string
}

func NewAuditLogger(logger *Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

func (a *AuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) {
	a.logger.Info(ctx, "AUDIT",
		zap.String("event_type", event.Type),
		zap.Uint64("user_id", event.UserID),
		zap.String("action", event.Action),
		zap.String("resource", event.Resource),
		zap.Bool("success", event.Success),
		zap.String("ip_address", event.IPAddress),
	)
}
