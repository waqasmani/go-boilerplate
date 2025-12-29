package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/waqasmani/go-boilerplate/internal/config"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"github.com/waqasmani/go-boilerplate/internal/shared/errors"
	"github.com/waqasmani/go-boilerplate/internal/shared/utils"
	"go.uber.org/zap"
)

func ErrorHandlingMiddleware(logger *observability.Logger, metrics *observability.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Process any errors that occurred during request handling
		if len(c.Errors) > 0 {
			// Get the last error (most relevant)
			err := c.Errors.Last().Err

			// Try to cast to AppError for structured handling
			appErr, ok := err.(*errors.AppError)
			if !ok {
				// If not an AppError, wrap it appropriately
				if c.Writer.Status() >= 500 {
					appErr = errors.Wrap(err, errors.ErrCodeInternal, "Internal server error")
				} else {
					appErr = errors.Wrap(err, errors.ErrCodeBadRequest, "Request processing error")
				}
			}

			// Record error metric
			if metrics != nil {
				metrics.RecordError(appErr.ErrorType, c.Request.Method, c.FullPath())
			}

			// Log the error with correlation IDs
			ctx := c.Request.Context()
			fields := []zap.Field{
				logger.Field("path", c.Request.URL.Path),
				logger.Field("method", c.Request.Method),
				logger.Field("status_code", c.Writer.Status()),
				logger.Field("error_type", appErr.ErrorType),
				logger.Field("error_code", appErr.Code),
			}

			if appErr.Err != nil {
				fields = append(fields, logger.Field("original_error", appErr.Err.Error()))
			}

			if appErr.Details != nil {
				fields = append(fields, logger.Field("details", appErr.Details))
			}

			if appErr.ErrorType == errors.ErrorTypeServer {
				logger.Error(ctx, "Server error occurred", fields...)
			} else {
				logger.Warn(ctx, "Client error occurred", fields...)
			}

			// Don't overwrite response if it's already been written
			if !c.Writer.Written() {
				utils.Error(c, appErr)
			}
		}
	}
}

func TracingMiddleware(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract tracing context from headers
		traceID := c.GetHeader("X-Request-ID")
		if traceID == "" {
			id, _ := uuid.NewRandom()
			traceID = id.String()
		}

		// Create a new context with trace ID
		ctx := context.WithValue(c.Request.Context(), observability.TraceIDKey, traceID)
		c.Request = c.Request.WithContext(ctx)

		// Log the trace ID for correlation
		logger.Debug(ctx, "Trace started",
			logger.Field("trace_id", traceID),
			logger.Field("path", c.Request.URL.Path),
			logger.Field("method", c.Request.Method),
		)

		c.Next()
	}
}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			id, _ := uuid.NewRandom()
			requestID = id.String()
		}

		ctx := context.WithValue(c.Request.Context(), observability.RequestIDKey, requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Set(string(observability.RequestIDKey), requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// TimeoutMiddleware attaches a timeout to the request context.
// Downstream handlers (DB, API calls) using this context will automatically cancel if the timeout is reached.
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		// Update the request with the new context
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func NewCORSMiddleware(cfg config.CORSConfig) gin.HandlerFunc {
	corsCfg := cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     cfg.AllowedMethods,
		AllowHeaders:     append(cfg.AllowedHeaders, "X-CSRF-Token", "X-Request-ID"),
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-CSRF-Token"},
	}

	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			corsCfg.AllowAllOrigins = true
			corsCfg.AllowOrigins = nil
			break
		}
	}

	return cors.New(corsCfg)
}

// SecurityHeadersMiddleware injects common security-related HTTP headers.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}

func LoggerMiddleware(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		userAgent := c.Request.UserAgent()
		clientIP := c.ClientIP()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		fields := []zap.Field{
			logger.Field("method", method),
			logger.Field("path", path),
			logger.Field("status", statusCode),
			logger.Field("latency_ms", latency.Milliseconds()),
			logger.Field("client_ip", clientIP),
			logger.Field("user_agent", userAgent),
		}

		if len(c.Errors) > 0 {
			fields = append(fields, logger.Field("errors", c.Errors.String()))
		}

		if statusCode >= 500 {
			logger.Error(c.Request.Context(), "HTTP Request completed with server error", fields...)
		} else if statusCode >= 400 {
			logger.Warn(c.Request.Context(), "HTTP Request completed with client error", fields...)
		} else {
			logger.Info(c.Request.Context(), "HTTP Request completed", fields...)
		}
	}
}

func MetricsMiddleware(metrics *observability.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}
		method := c.Request.Method

		c.Next()

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", c.Writer.Status())

		metrics.HttpRequestsTotal.WithLabelValues(method, path, status).Inc()
		metrics.HttpRequestDuration.WithLabelValues(method, path).Observe(duration)

		if c.Request.ContentLength > 0 {
			metrics.HttpRequestSize.WithLabelValues(method, path).Observe(float64(c.Request.ContentLength))
		}

		responseSize := c.Writer.Size()
		if responseSize > 0 {
			metrics.HttpResponseSize.WithLabelValues(method, path).Observe(float64(responseSize))
		}
	}
}

func PanicRecoveryMiddleware(logger *observability.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error(c.Request.Context(), "Panic recovered",
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
				)

				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error": gin.H{
						"code":    "INTERNAL_ERROR",
						"message": "Internal server error",
					},
				})
			}
		}()
		c.Next()
	}
}

// BodyLimitMiddleware restricts the maximum size of the request body to prevent OOM attacks.
func BodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use http.MaxBytesReader to enforce the limit at the reader level
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
