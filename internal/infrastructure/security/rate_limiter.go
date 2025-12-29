package security

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimiter defines the interface for rate limiting strategies
type RateLimiter interface {
	Allow(ctx context.Context, identifier string, limit int, window time.Duration) (bool, error)
	Reset(ctx context.Context, identifier string) error
	GetRemaining(ctx context.Context, identifier string, limit int, window time.Duration) (int, error)
}

// Configuration for sharded in-memory limiter
const (
	// Total max clients across all shards to prevent OOM
	MaxTrackedClients = 100000
	// ShardCount determines the granularity of locking (Power of 2 is preferred)
	ShardCount = 32
	// Per-shard limit
	MaxTrackedClientsPerShard = MaxTrackedClients / ShardCount
)

// bucketInfo holds the rate limit state for a single client using Fixed Window
type bucketInfo struct {
	count   int
	resetAt time.Time
}

// rateLimitShard represents a slice of the rate limiter with its own lock
type rateLimitShard struct {
	mu       sync.RWMutex
	requests map[string]*bucketInfo
}

// InMemoryRateLimiter implements a thread-safe, sharded fixed-window limiter
type InMemoryRateLimiter struct {
	shards []*rateLimitShard
	stopCh chan struct{}
}

// NewInMemoryRateLimiter initializes the sharded limiter and starts the cleanup routine
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	rl := &InMemoryRateLimiter{
		shards: make([]*rateLimitShard, ShardCount),
		stopCh: make(chan struct{}),
	}

	// Initialize shards
	for i := 0; i < ShardCount; i++ {
		rl.shards[i] = &rateLimitShard{
			requests: make(map[string]*bucketInfo),
		}
	}

	go rl.cleanup()
	return rl
}

// getShard maps an identifier to a specific shard index using FNV hashing
func (rl *InMemoryRateLimiter) getShard(identifier string) *rateLimitShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(identifier))
	idx := h.Sum32() % uint32(ShardCount)
	return rl.shards[idx]
}

// cleanup runs in the background to remove expired entries
func (rl *InMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for _, shard := range rl.shards {
				// Lock only this shard for cleanup
				shard.mu.Lock()
				for key, bucket := range shard.requests {
					if now.After(bucket.resetAt) {
						delete(shard.requests, key)
					}
				}
				shard.mu.Unlock()
			}
		case <-rl.stopCh:
			return // Graceful shutdown
		}
	}
}

// Allow checks if the request is allowed within the rate limit
func (rl *InMemoryRateLimiter) Allow(ctx context.Context, identifier string, limit int, window time.Duration) (bool, error) {
	shard := rl.getShard(identifier)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	bucket, exists := shard.requests[identifier]

	// Handle new clients
	if !exists {
		// Enforce memory bounds per shard
		if len(shard.requests) >= MaxTrackedClientsPerShard {
			// Prune expired entries in this shard immediately
			rl.pruneShard(shard, now)

			// If still full, fail closed to protect memory
			if len(shard.requests) >= MaxTrackedClientsPerShard {
				return false, errors.New("rate limit capacity exceeded")
			}
		}

		bucket = &bucketInfo{
			count:   0,
			resetAt: now.Add(window),
		}
		shard.requests[identifier] = bucket
	}

	// Fixed Window Logic: Reset if the window has expired
	if now.After(bucket.resetAt) {
		bucket.count = 0
		bucket.resetAt = now.Add(window)
	}

	if bucket.count >= limit {
		return false, nil
	}

	bucket.count++
	return true, nil
}

// pruneShard removes expired entries from a specific shard
// Caller must hold the shard lock
func (rl *InMemoryRateLimiter) pruneShard(shard *rateLimitShard, now time.Time) {
	for key, bucket := range shard.requests {
		if now.After(bucket.resetAt) {
			delete(shard.requests, key)
		}
	}
}

// Reset clears the rate limit for a specific identifier
func (rl *InMemoryRateLimiter) Reset(ctx context.Context, identifier string) error {
	shard := rl.getShard(identifier)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	delete(shard.requests, identifier)
	return nil
}

// GetRemaining calculates remaining requests for an identifier
func (rl *InMemoryRateLimiter) GetRemaining(ctx context.Context, identifier string, limit int, window time.Duration) (int, error) {
	shard := rl.getShard(identifier)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	bucket, exists := shard.requests[identifier]
	if !exists {
		return limit, nil
	}

	now := time.Now()

	// If window expired, full limit is available
	if now.After(bucket.resetAt) {
		return limit, nil
	}

	remaining := limit - bucket.count
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

// RedisRateLimiter implementation (Unchanged)
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

// RouteRateLimitMiddleware applies rate limiting to a gin route
func RouteRateLimitMiddleware(rl RateLimiter, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.ClientIP()

		allowed, err := rl.Allow(c.Request.Context(), identifier, limit, window)
		if err != nil {
			// Fail open on internal error to allow traffic, or log error
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

func (rl *InMemoryRateLimiter) Stop() {
	close(rl.stopCh)
}
