package observability

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
)

// MetricsConfig holds configuration for metrics initialization
type MetricsConfig struct {
	Namespace string
	Subsystem string
	Registry  prometheus.Registerer
	Gatherer  prometheus.Gatherer
}

// DefaultMetricsConfig returns a config using the default Prometheus registry
func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Namespace: "api",
		Subsystem: "",
		Registry:  prometheus.DefaultRegisterer,
		Gatherer:  prometheus.DefaultGatherer,
	}
}

// Metrics holds all Prometheus metrics collectors
type Metrics struct {
	HttpRequestsTotal        *prometheus.CounterVec
	HttpRequestDuration      *prometheus.HistogramVec
	HttpRequestSize          *prometheus.HistogramVec
	HttpResponseSize         *prometheus.HistogramVec
	DatabaseQueryDuration    *prometheus.HistogramVec
	DatabaseQuerySuccess     *prometheus.CounterVec
	DatabaseQueryErrors      *prometheus.CounterVec
	DatabaseConnections      *prometheus.GaugeVec
	DatabaseRetryAttempts    *prometheus.CounterVec
	DatabaseRetrySkipped     *prometheus.CounterVec
	DatabaseRetryMaxAttempts *prometheus.CounterVec
	CacheHits                *prometheus.CounterVec
	CacheMisses              *prometheus.CounterVec
	AuthenticationAttempts   *prometheus.CounterVec
	AuthenticationFailures   *prometheus.CounterVec
	TokenRefreshes           *prometheus.CounterVec
	CSRFValidations          *prometheus.CounterVec
	RateLimitHits            *prometheus.CounterVec
	ActiveSessions           prometheus.Gauge
	BackgroundJobDuration    *prometheus.HistogramVec
	BackgroundJobErrors      *prometheus.CounterVec
	ErrorCount               *prometheus.CounterVec
	ClientErrorCount         *prometheus.CounterVec
	ServerErrorCount         *prometheus.CounterVec
	NetworkErrorCount        *prometheus.CounterVec
	CircuitBreakerState      *prometheus.GaugeVec
	CircuitBreakerEvents     *prometheus.CounterVec
	CircuitBreakerDuration   *prometheus.SummaryVec
	CheckInsTotal            *prometheus.CounterVec
	CheckOutsTotal           *prometheus.CounterVec
	TimeOffRequestsTotal     *prometheus.CounterVec
	AttendanceDuration       *prometheus.HistogramVec
	registry                 prometheus.Registerer
	gatherer                 prometheus.Gatherer
}

var (
	metrics     *Metrics
	metricsOnce sync.Once
)

// NewMetrics creates a new Metrics instance with the provided configuration
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metrics = NewMetricsWithConfig(DefaultMetricsConfig())
	})
	return metrics
}

// NewMetricsWithConfig creates a new Metrics instance with custom configuration
func NewMetricsWithConfig(cfg MetricsConfig) *Metrics {
	// Create a factory with the custom registry
	factory := promauto.With(cfg.Registry)
	m := &Metrics{
		registry: cfg.Registry,
		gatherer: cfg.Gatherer,
	}

	// HTTP Metrics
	m.HttpRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)
	m.HttpRequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_request_duration_seconds",
			Help:      "Duration of HTTP requests in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)
	m.HttpRequestSize = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_request_size_bytes",
			Help:      "Size of HTTP requests in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)
	m.HttpResponseSize = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "http_response_size_bytes",
			Help:      "Size of HTTP responses in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	// Database Metrics
	m.DatabaseQueryDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_query_duration_seconds",
			Help:      "Duration of database queries in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"query_type", "table"},
	)
	m.DatabaseQuerySuccess = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_query_success_total",
			Help:      "Total number of successful database queries",
		},
		[]string{"query_type", "table"},
	)
	m.DatabaseQueryErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_query_errors_total",
			Help:      "Total number of database query errors",
		},
		[]string{"query_type", "table", "error_type"},
	)
	m.DatabaseConnections = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_connections",
			Help:      "Number of active database connections",
		},
		[]string{"state"},
	)
	m.DatabaseRetryAttempts = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_retry_attempts_total",
			Help:      "Total number of database operation retry attempts",
		},
		[]string{"operation", "error_type"},
	)
	m.DatabaseRetrySkipped = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_retry_skipped_total",
			Help:      "Total number of database operations that were not retried due to error type",
		},
		[]string{"operation", "error_type"},
	)
	m.DatabaseRetryMaxAttempts = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "database_retry_max_attempts_total",
			Help:      "Total number of database operations that reached max retry attempts",
		},
		[]string{"operation"},
	)

	// Cache Metrics
	m.CacheHits = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"cache_name"},
	)
	m.CacheMisses = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
		[]string{"cache_name"},
	)

	// Authentication Metrics
	m.AuthenticationAttempts = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "authentication_attempts_total",
			Help:      "Total number of authentication attempts",
		},
		[]string{"method"},
	)
	m.AuthenticationFailures = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "authentication_failures_total",
			Help:      "Total number of authentication failures",
		},
		[]string{"method", "reason"},
	)
	m.TokenRefreshes = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "token_refreshes_total",
			Help:      "Total number of token refreshes",
		},
		[]string{"status"},
	)
	m.CSRFValidations = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "csrf_validations_total",
			Help:      "Total number of CSRF validations",
		},
		[]string{"status"},
	)

	// Rate Limiting Metrics
	m.RateLimitHits = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "rate_limit_hits_total",
			Help:      "Total number of rate limit hits",
		},
		[]string{"route", "identifier"},
	)
	m.ActiveSessions = factory.NewGauge(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "active_sessions",
			Help:      "Number of active user sessions",
		},
	)

	// Background Job Metrics
	m.BackgroundJobDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "background_job_duration_seconds",
			Help:      "Duration of background jobs in seconds",
			Buckets:   []float64{.1, .5, 1, 5, 10, 30, 60, 300},
		},
		[]string{"job_name"},
	)
	m.BackgroundJobErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "background_job_errors_total",
			Help:      "Total number of background job errors",
		},
		[]string{"job_name", "error_type"},
	)

	// Error Metrics
	m.ErrorCount = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "error_total",
			Help:      "Total number of errors by type",
		},
		[]string{"error_type", "method", "path"},
	)
	m.ClientErrorCount = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "client_error_total",
			Help:      "Total number of client errors",
		},
		[]string{"error_code", "method", "path"},
	)
	m.ServerErrorCount = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "server_error_total",
			Help:      "Total number of server errors",
		},
		[]string{"error_code", "method", "path"},
	)
	m.NetworkErrorCount = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "network_error_total",
			Help:      "Total number of network errors",
		},
		[]string{"error_code", "method", "path"},
	)

	// Circuit Breaker Metrics
	m.CircuitBreakerState = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "circuit_breaker_state",
			Help:      "Current state of circuit breakers (0=closed, 0.5=half_open, 1=open)",
		},
		[]string{"name", "state"},
	)
	m.CircuitBreakerEvents = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: cfg.Namespace,
			Subsystem: cfg.Subsystem,
			Name:      "circuit_breaker_events_total",
			Help:      "Total number of circuit breaker events",
		},
		[]string{"name", "event_type", "reason"},
	)
	m.CircuitBreakerDuration = factory.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:  cfg.Namespace,
			Subsystem:  cfg.Subsystem,
			Name:       "circuit_breaker_duration_seconds",
			Help:       "Duration of operations protected by circuit breakers",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"name", "status"},
	)

	// Attendance Metrics
	m.CheckInsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attendance_check_ins_total",
			Help: "Total number of check-ins",
		},
		[]string{"status"},
	)

	m.CheckOutsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "attendance_check_outs_total",
			Help: "Total number of check-outs",
		},
		[]string{"status"},
	)

	m.TimeOffRequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "time_off_requests_total",
			Help: "Total time off requests",
		},
		[]string{"leave_type", "status"},
	)

	m.AttendanceDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "attendance_duration_seconds",
			Help:    "Distribution of attendance session durations",
			Buckets: prometheus.ExponentialBuckets(3600, 2, 10),
		},
		[]string{"shift"},
	)

	return m
}

// RecordDatabaseStats records database connection pool statistics
func (m *Metrics) RecordDatabaseStats(openConns, inUse, idle int) {
	m.DatabaseConnections.WithLabelValues("open").Set(float64(openConns))
	m.DatabaseConnections.WithLabelValues("in_use").Set(float64(inUse))
	m.DatabaseConnections.WithLabelValues("idle").Set(float64(idle))
}

// RecordBackgroundJob records metrics for background job execution
func (m *Metrics) RecordBackgroundJob(jobName string, duration time.Duration, err error) {
	m.BackgroundJobDuration.WithLabelValues(jobName).Observe(duration.Seconds())
	if err != nil {
		m.BackgroundJobErrors.WithLabelValues(jobName, "error").Inc()
	}
}

// RecordError records error metrics by type
func (m *Metrics) RecordError(errorType errors.ErrorType, method, path string) {
	m.ErrorCount.WithLabelValues(string(errorType), method, path).Inc()
	// Record specific error type metrics for better granularity
	switch errorType {
	case errors.ErrorTypeClient:
		m.ClientErrorCount.WithLabelValues("client_error", method, path).Inc()
	case errors.ErrorTypeServer:
		m.ServerErrorCount.WithLabelValues("server_error", method, path).Inc()
	case errors.ErrorTypeNetwork:
		m.NetworkErrorCount.WithLabelValues("network_error", method, path).Inc()
	}
}

// Registry returns the Prometheus registry used by this Metrics instance
func (m *Metrics) Registry() prometheus.Registerer {
	return m.registry
}

// Gatherer returns the Prometheus gatherer used by this Metrics instance
func (m *Metrics) Gatherer() prometheus.Gatherer {
	return m.gatherer
}

// Unregister removes all metrics from the registry
// Useful for testing to prevent metric collisions
func (m *Metrics) Unregister() {
	if m.registry == nil {
		return
	}
	collectors := []prometheus.Collector{
		m.HttpRequestsTotal,
		m.HttpRequestDuration,
		m.HttpRequestSize,
		m.HttpResponseSize,
		m.DatabaseQueryDuration,
		m.DatabaseQuerySuccess,
		m.DatabaseQueryErrors,
		m.DatabaseConnections,
		m.DatabaseRetryAttempts,
		m.DatabaseRetrySkipped,
		m.DatabaseRetryMaxAttempts,
		m.CacheHits,
		m.CacheMisses,
		m.AuthenticationAttempts,
		m.AuthenticationFailures,
		m.TokenRefreshes,
		m.CSRFValidations,
		m.RateLimitHits,
		m.ActiveSessions,
		m.BackgroundJobDuration,
		m.BackgroundJobErrors,
		m.ErrorCount,
		m.ClientErrorCount,
		m.ServerErrorCount,
		m.NetworkErrorCount,
		m.CircuitBreakerState,
		m.CircuitBreakerEvents,
		m.CircuitBreakerDuration,
		m.CheckInsTotal,
		m.CheckOutsTotal,
		m.TimeOffRequestsTotal,
		m.AttendanceDuration,
	}
	for _, collector := range collectors {
		m.registry.Unregister(collector)
	}
}
