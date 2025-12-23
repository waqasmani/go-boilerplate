package health

import (
	"context"
	"database/sql"
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
)

type Handler struct {
	db        *sql.DB
	startTime time.Time
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{
		db:        db,
		startTime: time.Now(),
	}
}

type HealthResponse struct {
	Status   string         `json:"status"`
	Version  string         `json:"version"`
	Uptime   string         `json:"uptime"`
	Database DatabaseHealth `json:"database"`
	System   SystemHealth   `json:"system"`
}

type DatabaseHealth struct {
	Status          string `json:"status"`
	OpenConnections int    `json:"open_connections"`
	InUse           int    `json:"in_use"`
	Idle            int    `json:"idle"`
	MaxOpenConns    int    `json:"max_open_conns"`
}

type SystemHealth struct {
	NumGoroutine int    `json:"num_goroutine"`
	MemAllocMB   uint64 `json:"mem_alloc_mb"`
	NumCPU       int    `json:"num_cpu"`
}

// @Summary Check API health
// @Description Get comprehensive health status of the API including database connectivity and system metrics
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health [get]
func (h *Handler) Health(c *gin.Context) {
	dbHealth := h.getDatabaseHealth(c.Request.Context())
	systemHealth := h.getSystemHealth()

	overallStatus := "ok"
	if dbHealth.Status != "ok" {
		overallStatus = "degraded"
	}

	utils.Success(c, http.StatusOK, HealthResponse{
		Status:   overallStatus,
		Version:  "1.0.0",
		Uptime:   time.Since(h.startTime).String(),
		Database: dbHealth,
		System:   systemHealth,
	})
}

// @Summary Check API readiness
// @Description Check if API is ready to serve traffic (database connectivity check)
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 503 {object} HealthResponse
// @Router /ready [get]
func (h *Handler) Ready(c *gin.Context) {
	dbStatus := h.checkDatabase(c.Request.Context())
	if dbStatus != "ok" {
		utils.Success(c, http.StatusServiceUnavailable, HealthResponse{
			Status: "not ready",
			Database: DatabaseHealth{
				Status: dbStatus,
			},
		})
		return
	}
	utils.Success(c, http.StatusOK, HealthResponse{
		Status: "ready",
		Database: DatabaseHealth{
			Status: "ok",
		},
	})
}

// @Summary Check API liveness
// @Description Lightweight check to verify API process is running
// @Tags health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /alive [get]
func (h *Handler) Alive(c *gin.Context) {
	utils.Success(c, http.StatusOK, gin.H{
		"status": "alive",
	})
}

func (h *Handler) checkDatabase(ctx context.Context) string {
	dbCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := h.db.PingContext(dbCtx); err != nil {
		return "error"
	}
	return "ok"
}

func (h *Handler) getDatabaseHealth(ctx context.Context) DatabaseHealth {
	status := h.checkDatabase(ctx)
	stats := h.db.Stats()

	return DatabaseHealth{
		Status:          status,
		OpenConnections: stats.OpenConnections,
		InUse:           stats.InUse,
		Idle:            stats.Idle,
		MaxOpenConns:    stats.MaxOpenConnections,
	}
}

func (h *Handler) getSystemHealth() SystemHealth {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemHealth{
		NumGoroutine: runtime.NumGoroutine(),
		MemAllocMB:   m.Alloc / 1024 / 1024,
		NumCPU:       runtime.NumCPU(),
	}
}
