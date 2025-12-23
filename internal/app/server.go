package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Server struct {
	router     *gin.Engine
	container  *Container
	httpServer *http.Server
}

func NewServer(container *Container) *Server {
	router := SetupRouter(container)
	return &Server{
		router:    router,
		container: container,
	}
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.startBackgroundWorkers(ctx)
	s.startMetricsCollector(ctx)

	addr := fmt.Sprintf("%s:%s", s.container.Config.Server.Host, s.container.Config.Server.Port)
	s.httpServer = &http.Server{
		Addr:           addr,
		Handler:        s.router,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.container.Logger.Info(context.Background(),
		fmt.Sprintf("Starting server on %s", addr),
		zap.String("env", s.container.Config.Server.Env),
	)

	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	default:
		return s.waitForShutdown(cancel)
	}
}

func (s *Server) startBackgroundWorkers(ctx context.Context) {
	interval := s.container.Config.Security.RefreshTokenCleanupInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.container.Logger.Info(ctx, "Starting background workers",
			zap.Duration("cleanup_interval", interval))

		for {
			select {
			case <-ticker.C:
				s.cleanupExpiredTokens(ctx)
			case <-ctx.Done():
				s.container.Logger.Info(ctx, "Stopping background workers...")
				return
			}
		}
	}()
}

func (s *Server) startMetricsCollector(ctx context.Context) {
	if !s.container.Config.Metrics.Enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.collectDatabaseMetrics(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) collectDatabaseMetrics(ctx context.Context) {
	stats := s.container.DB.Stats()
	s.container.Metrics.RecordDatabaseStats(
		stats.OpenConnections,
		stats.InUse,
		stats.Idle,
	)
}

func (s *Server) cleanupExpiredTokens(ctx context.Context) {
	start := time.Now()
	jobName := "token_cleanup"

	defer func() {
		duration := time.Since(start)
		if r := recover(); r != nil {
			s.container.Logger.Error(ctx, "Panic in cleanup job",
				zap.Any("error", r),
				zap.String("job", jobName))
			s.container.Metrics.RecordBackgroundJob(jobName, duration, fmt.Errorf("panic: %v", r))
		}
	}()

	err := s.container.Queries.DeleteExpiredRefreshTokens(ctx)
	duration := time.Since(start)

	if err != nil {
		s.container.Logger.Error(ctx, "Failed to clean up expired refresh tokens",
			zap.Error(err),
			zap.Duration("duration", duration))
		s.container.Metrics.RecordBackgroundJob(jobName, duration, err)
		return
	}

	s.container.Logger.Info(ctx, "Cleaned up expired refresh tokens",
		zap.Duration("duration", duration))
	s.container.Metrics.RecordBackgroundJob(jobName, duration, nil)
}

func (s *Server) waitForShutdown(cancel context.CancelFunc) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	s.container.Logger.Info(context.Background(), "Shutting down server...")

	cancel()

	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()

	if err := s.gracefulShutdown(ctx); err != nil {
		s.container.Logger.Error(context.Background(), "Graceful shutdown failed", zap.Error(err))
		return err
	}

	s.container.Logger.Info(context.Background(), "Server shutdown complete")
	return nil
}

func (s *Server) gracefulShutdown(ctx context.Context) error {
	// Stop accepting new requests first
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("HTTP server shutdown failed: %w", err)
	}
	// Allow in-flight requests to complete with extended deadline
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.container.DB.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("database close failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("database close timeout: %w", ctx.Err())
	}
}

func (s *Server) Stats() ServerStats {
	dbStats := s.container.DB.Stats()
	return ServerStats{
		OpenConnections: dbStats.OpenConnections,
		InUse:           dbStats.InUse,
		Idle:            dbStats.Idle,
	}
}

type ServerStats struct {
	OpenConnections int
	InUse           int
	Idle            int
}
