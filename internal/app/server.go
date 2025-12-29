package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Server struct {
	router       *gin.Engine
	container    *Container
	httpServer   *http.Server
	workerCtx    context.Context
	workerCancel context.CancelFunc
	workerWG     sync.WaitGroup
}

func NewServer(container *Container) *Server {
	router := SetupRouter(container)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	return &Server{
		router:       router,
		container:    container,
		workerCtx:    workerCtx,
		workerCancel: workerCancel,
	}
}

func (s *Server) Start() error {
	s.startBackgroundWorkers()
	s.startMetricsCollector()
	addr := fmt.Sprintf("%s:%s", s.container.Config.Server.Host, s.container.Config.Server.Port)
	s.httpServer = &http.Server{
		Addr:           addr,
		Handler:        s.router,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.container.Logger.Info(s.workerCtx,
		fmt.Sprintf("Starting server on %s", addr),
		zap.String("env", s.container.Config.Server.Env),
	)

	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server failed: %w", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return err
	case sig := <-sigChan:
		s.container.Logger.Info(s.workerCtx, "Shutdown signal received", zap.String("signal", sig.String()))
		return s.gracefulShutdown()
	}
}

func (s *Server) startBackgroundWorkers() {
	interval := s.container.Config.Security.RefreshTokenCleanupInterval
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	s.workerWG.Add(1)
	go func() {
		defer s.workerWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		s.container.Logger.Info(s.workerCtx, "Starting background workers", zap.Duration("cleanup_interval", interval))
		for {
			select {
			case <-ticker.C:
				s.cleanupExpiredTokens()
			case <-s.workerCtx.Done():
				s.container.Logger.Info(s.workerCtx, "Stopping background workers...")
				return
			}
		}
	}()
}

func (s *Server) startMetricsCollector() {
	if !s.container.Config.Metrics.Enabled {
		return
	}
	s.workerWG.Add(1)
	go func() {
		defer s.workerWG.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			// Prioritize shutdown signal in the select logic
			case <-s.workerCtx.Done():
				return
			case <-ticker.C:
				// Double-check context to prevent starting work during race conditions
				if s.workerCtx.Err() != nil {
					return
				}
				s.collectDatabaseMetrics()
			}
		}
	}()
}

func (s *Server) collectDatabaseMetrics() {
	stats := s.container.DB.Stats()
	s.container.Metrics.RecordDatabaseStats(
		stats.OpenConnections,
		stats.InUse,
		stats.Idle,
	)
}

func (s *Server) cleanupExpiredTokens() {
	start := time.Now()
	jobName := "token_cleanup"
	ctx := s.workerCtx
	defer func() {
		duration := time.Since(start)
		if r := recover(); r != nil {
			s.container.Logger.Error(ctx, "Panic in cleanup job", zap.Any("error", r), zap.String("job", jobName))
			s.container.Metrics.RecordBackgroundJob(jobName, duration, fmt.Errorf("panic: %v", r))
		}
	}()

	batchSize := int32(s.container.Config.Security.RefreshTokenCleanupBatchSize)
	totalDeleted := int64(0)

	for {
		select {
		case <-ctx.Done():
			s.container.Logger.Info(ctx, "Token cleanup interrupted, exiting")
			return
		default:
		}

		batchCtx, batchCancel := context.WithTimeout(ctx, 30*time.Second)
		defer batchCancel()

		result, err := s.container.Queries.DeleteExpiredRefreshTokens(batchCtx, batchSize)
		if err != nil {
			duration := time.Since(start)
			s.container.Logger.Error(ctx, "Failed to clean up expired refresh tokens", zap.Error(err), zap.Duration("duration", duration))
			s.container.Metrics.RecordBackgroundJob(jobName, duration, err)
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			s.container.Logger.Error(ctx, "Failed to get rows affected", zap.Error(err))
			return
		}

		totalDeleted += rowsAffected
		if rowsAffected < int64(batchSize) {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	duration := time.Since(start)
	if totalDeleted > 0 {
		s.container.Logger.Info(ctx, "Cleaned up expired refresh tokens", zap.Int64("count", totalDeleted), zap.Duration("duration", duration))
	}
	s.container.Metrics.RecordBackgroundJob(jobName, duration, nil)
}

func (s *Server) gracefulShutdown() error {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	s.container.Logger.Info(s.workerCtx, "Shutting down HTTP server...")
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		s.container.Logger.Error(s.workerCtx, "HTTP server shutdown failed", zap.Error(err))
	}

	s.container.Logger.Info(s.workerCtx, "Stopping background workers...")
	s.workerCancel()

	shutdownDone := make(chan struct{})
	go func() {
		s.workerWG.Wait()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		s.container.Logger.Info(s.workerCtx, "Background workers finished")
	case <-time.After(10 * time.Second):
		s.container.Logger.Warn(s.workerCtx, "Background workers did not finish in time, proceeding with shutdown")
	}

	s.container.Logger.Info(s.workerCtx, "Closing infrastructure connections...")
	s.container.Close()
	s.container.Logger.Info(s.workerCtx, "Server exited gracefully")
	return nil
}
