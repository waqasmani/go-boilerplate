package observability

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metrics     *Metrics
	metricsOnce sync.Once
)

type Metrics struct {
	HttpRequestsTotal       *prometheus.CounterVec
	HttpRequestDuration     *prometheus.HistogramVec
	HttpRequestSize         *prometheus.HistogramVec
	HttpResponseSize        *prometheus.HistogramVec
	DatabaseQueryDuration   *prometheus.HistogramVec
	DatabaseQuerySuccess    *prometheus.CounterVec
	DatabaseQueryErrors     *prometheus.CounterVec
	DatabaseConnections     *prometheus.GaugeVec
	CacheHits               *prometheus.CounterVec
	CacheMisses             *prometheus.CounterVec
	AuthenticationAttempts  *prometheus.CounterVec
	AuthenticationFailures  *prometheus.CounterVec
	TokenRefreshes          *prometheus.CounterVec
	CSRFValidations         *prometheus.CounterVec
	RateLimitHits           *prometheus.CounterVec
	ActiveSessions          prometheus.Gauge
	BackgroundJobDuration   *prometheus.HistogramVec
	BackgroundJobErrors     *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		metrics = &Metrics{
			HttpRequestsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "http_requests_total",
					Help: "Total number of HTTP requests",
				},
				[]string{"method", "path", "status"},
			),
			HttpRequestDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "http_request_duration_seconds",
					Help:    "Duration of HTTP requests in seconds",
					Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
				},
				[]string{"method", "path"},
			),
			HttpRequestSize: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "http_request_size_bytes",
					Help:    "Size of HTTP requests in bytes",
					Buckets: prometheus.ExponentialBuckets(100, 10, 8),
				},
				[]string{"method", "path"},
			),
			HttpResponseSize: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "http_response_size_bytes",
					Help:    "Size of HTTP responses in bytes",
					Buckets: prometheus.ExponentialBuckets(100, 10, 8),
				},
				[]string{"method", "path"},
			),
			DatabaseQueryDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "database_query_duration_seconds",
					Help:    "Duration of database queries in seconds",
					Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
				},
				[]string{"query_type", "table"},
			),
			DatabaseQuerySuccess: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "database_query_success_total",
					Help: "Total number of successful database queries",
				},
				[]string{"query_type", "table"},
			),
			DatabaseQueryErrors: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "database_query_errors_total",
					Help: "Total number of database query errors",
				},
				[]string{"query_type", "table", "error_type"},
			),
			DatabaseConnections: promauto.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: "database_connections",
					Help: "Number of active database connections",
				},
				[]string{"state"},
			),
			CacheHits: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "cache_hits_total",
					Help: "Total number of cache hits",
				},
				[]string{"cache_name"},
			),
			CacheMisses: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "cache_misses_total",
					Help: "Total number of cache misses",
				},
				[]string{"cache_name"},
			),
			AuthenticationAttempts: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "authentication_attempts_total",
					Help: "Total number of authentication attempts",
				},
				[]string{"method"},
			),
			AuthenticationFailures: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "authentication_failures_total",
					Help: "Total number of authentication failures",
				},
				[]string{"method", "reason"},
			),
			TokenRefreshes: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "token_refreshes_total",
					Help: "Total number of token refreshes",
				},
				[]string{"status"},
			),
			CSRFValidations: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "csrf_validations_total",
					Help: "Total number of CSRF validations",
				},
				[]string{"status"},
			),
			RateLimitHits: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "rate_limit_hits_total",
					Help: "Total number of rate limit hits",
				},
				[]string{"route", "identifier"},
			),
			ActiveSessions: promauto.NewGauge(
				prometheus.GaugeOpts{
					Name: "active_sessions",
					Help: "Number of active user sessions",
				},
			),
			BackgroundJobDuration: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "background_job_duration_seconds",
					Help:    "Duration of background jobs in seconds",
					Buckets: []float64{.1, .5, 1, 5, 10, 30, 60, 300},
				},
				[]string{"job_name"},
			),
			BackgroundJobErrors: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "background_job_errors_total",
					Help: "Total number of background job errors",
				},
				[]string{"job_name", "error_type"},
			),
		}
	})
	return metrics
}

func (m *Metrics) RecordDatabaseStats(openConns, inUse, idle int) {
	m.DatabaseConnections.WithLabelValues("open").Set(float64(openConns))
	m.DatabaseConnections.WithLabelValues("in_use").Set(float64(inUse))
	m.DatabaseConnections.WithLabelValues("idle").Set(float64(idle))
}

func (m *Metrics) RecordBackgroundJob(jobName string, duration time.Duration, err error) {
	m.BackgroundJobDuration.WithLabelValues(jobName).Observe(duration.Seconds())
	if err != nil {
		m.BackgroundJobErrors.WithLabelValues(jobName, "error").Inc()
	}
}