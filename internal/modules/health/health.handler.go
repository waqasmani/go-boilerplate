package health

import (
	"context"
	"database/sql"
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
)

type Handler struct {
	db           *sql.DB
	startTime    time.Time
	redisEnabled bool
	redisClient  func() (*redis.Client, error)
}

func NewHandler(db *sql.DB, redisEnabled bool) *Handler {
	return &Handler{
		db:           db,
		startTime:    time.Now(),
		redisEnabled: redisEnabled,
	}
}

func (h *Handler) SetRedisClientProvider(provider func() (*redis.Client, error)) {
	h.redisClient = provider
}

type HealthResponse struct {
	Status   string         `json:"status"`
	Version  string         `json:"version"`
	Uptime   string         `json:"uptime"`
	Database DatabaseHealth `json:"database"`
	Redis    *RedisHealth   `json:"redis,omitempty"`
	System   SystemHealth   `json:"system"`
}

type DatabaseHealth struct {
	Status          string `json:"status"`
	OpenConnections int    `json:"open_connections"`
	InUse           int    `json:"in_use"`
	Idle            int    `json:"idle"`
	MaxOpenConns    int    `json:"max_open_conns"`
}

type RedisHealth struct {
	Status  string `json:"status"`
	Latency string `json:"latency"`
}

type SystemHealth struct {
	NumGoroutine int    `json:"num_goroutine"`
	MemAllocMB   uint64 `json:"mem_alloc_mb"`
	NumCPU       int    `json:"num_cpu"`
}

// Health godoc
// @Summary Get health status
// @Description Get comprehensive health status of the application
// @Tags Health
// @Accept json
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

	response := HealthResponse{
		Status:   overallStatus,
		Version:  "1.0.0",
		Uptime:   time.Since(h.startTime).String(),
		Database: dbHealth,
		System:   systemHealth,
	}

	if h.redisEnabled && h.redisClient != nil {
		redisHealth := h.getRedisHealth(c.Request.Context())
		response.Redis = &redisHealth
		if redisHealth.Status != "ok" && overallStatus == "ok" {
			overallStatus = "degraded"
		}
		response.Status = overallStatus
	}

	utils.Success(c, http.StatusOK, response)
}

func (h *Handler) getRedisHealth(ctx context.Context) RedisHealth {
	if h.redisClient == nil {
		return RedisHealth{Status: "disabled"}
	}

	client, err := h.redisClient()
	if err != nil {
		return RedisHealth{Status: "error", Latency: err.Error()}
	}

	start := time.Now()
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return RedisHealth{Status: "error", Latency: err.Error()}
	}
	latency := time.Since(start).String()
	return RedisHealth{Status: "ok", Latency: latency}
}

// Ready godoc
// @Summary Get readiness status
// @Description Check if application is ready to serve traffic
// @Tags Health
// @Accept json
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

// Alive godoc
// @Summary Get liveness status
// @Description Check if application is alive
// @Tags Health
// @Accept json
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
