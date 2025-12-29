package attendance

import (
	"context"
	"time"

	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
)

// Scheduler handles background jobs
type Scheduler struct {
	service *Service
	logger  *observability.Logger
}

func NewScheduler(service *Service, logger *observability.Logger) *Scheduler {
	return &Scheduler{service: service, logger: logger}
}

// StartAutoCheckoutJob runs nightly to close stale sessions
func (s *Scheduler) StartAutoCheckoutJob(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			count, err := s.service.AutoCheckoutStaleSessions(ctx, 24)
			if err != nil {
				s.logger.Error(ctx, "Auto-checkout job failed", s.logger.Field("error", err))
			} else {
				s.logger.Info(ctx, "Auto-checkout completed", s.logger.Field("count", count))
			}
		case <-ctx.Done():
			return
		}
	}
}

// StartAccrualJob runs monthly to credit leave days
func (s *Scheduler) StartAccrualJob(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			if now.Day() == 1 { // First day of month
				// TODO: Implement accrual logic
				s.logger.Info(ctx, "Monthly accrual job executed")
			}
		case <-ctx.Done():
			return
		}
	}
}
