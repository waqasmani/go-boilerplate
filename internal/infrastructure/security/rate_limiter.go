package security

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type RateLimiter interface {
	Allow(ctx context.Context, identifier string, limit int, window time.Duration) (bool, error)
	Reset(ctx context.Context, identifier string) error
	GetRemaining(ctx context.Context, identifier string, limit int, window time.Duration) (int, error)
}

type InMemoryRateLimiter struct {
	mu       sync.Mutex
	requests map[string]*bucketInfo
}

type bucketInfo struct {
	timestamps []time.Time
	resetAt    time.Time
}

func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string]*bucketInfo),
	}
	go limiter.cleanup()
	return limiter
}

func (rl *InMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.requests {
			if now.After(bucket.resetAt) {
				delete(rl.requests, key)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *InMemoryRateLimiter) Allow(ctx context.Context, identifier string, limit int, window time.Duration) (bool, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-window)

	bucket, exists := rl.requests[identifier]
	if !exists {
		bucket = &bucketInfo{
			timestamps: []time.Time{now},
			resetAt:    now.Add(window),
		}
		rl.requests[identifier] = bucket
		return true, nil
	}

	var validRequests []time.Time
	for _, t := range bucket.timestamps {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= limit {
		return false, nil
	}

	bucket.timestamps = append(validRequests, now)
	bucket.resetAt = now.Add(window)
	return true, nil
}

func (rl *InMemoryRateLimiter) Reset(ctx context.Context, identifier string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.requests, identifier)
	return nil
}

func (rl *InMemoryRateLimiter) GetRemaining(ctx context.Context, identifier string, limit int, window time.Duration) (int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-window)

	bucket, exists := rl.requests[identifier]
	if !exists {
		return limit, nil
	}

	var validRequests []time.Time
	for _, t := range bucket.timestamps {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	remaining := limit - len(validRequests)
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

type RedisRateLimiter struct {
	client *redis.Client
	prefix string
}

func NewRedisRateLimiter(client *redis.Client) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		prefix: "rl:",
	}
}

func (rl *RedisRateLimiter) Allow(ctx context.Context, identifier string, limit int, window time.Duration) (bool, error) {
	key := fmt.Sprintf("%s%s", rl.prefix, identifier)

	pipe := rl.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("redis pipeline failed: %w", err)
	}

	count, err := incr.Result()
	if err != nil {
		return false, fmt.Errorf("redis incr failed: %w", err)
	}

	return count <= int64(limit), nil
}

func (rl *RedisRateLimiter) Reset(ctx context.Context, identifier string) error {
	key := fmt.Sprintf("%s%s", rl.prefix, identifier)
	return rl.client.Del(ctx, key).Err()
}

func (rl *RedisRateLimiter) GetRemaining(ctx context.Context, identifier string, limit int, window time.Duration) (int, error) {
	key := fmt.Sprintf("%s%s", rl.prefix, identifier)

	count, err := rl.client.Get(ctx, key).Int()
	if err == redis.Nil {
		return limit, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redis get failed: %w", err)
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

func RouteRateLimitMiddleware(rl RateLimiter, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.ClientIP()

		allowed, err := rl.Allow(c.Request.Context(), identifier, limit, window)
		if err != nil {
			c.Next()
			return
		}

		remaining, _ := rl.GetRemaining(c.Request.Context(), identifier, limit, window)

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))

		if !allowed {
			c.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "TOO_MANY_REQUESTS",
					"message": "Rate limit exceeded. Please try again later.",
				},
			})
			return
		}

		c.Next()
	}
}
