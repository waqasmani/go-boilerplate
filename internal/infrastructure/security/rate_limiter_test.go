package security

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryRateLimiter_Sharding(t *testing.T) {
	rl := NewInMemoryRateLimiter()
	ctx := context.Background()

	t.Run("Identifiers map to different shards", func(t *testing.T) {
		// We use enough identifiers to statistically guarantee they hit different shards
		shardsSeen := make(map[*rateLimitShard]bool)
		for i := 0; i < 100; i++ {
			id := fmt.Sprintf("user-%d", i)
			shard := rl.getShard(id)
			shardsSeen[shard] = true
		}

		// With 100 random IDs and 32 shards, we expect most/all shards to be touched
		assert.Greater(t, len(shardsSeen), 1, "Identifiers should be distributed across multiple shards")
	})

	t.Run("Sliding window across multiple shards", func(t *testing.T) {
		limit := 2
		window := 100 * time.Millisecond

		// Test user 1 (Shard A)
		allowed, _ := rl.Allow(ctx, "user-a", limit, window)
		assert.True(t, allowed)
		allowed, _ = rl.Allow(ctx, "user-a", limit, window)
		assert.True(t, allowed)
		allowed, _ = rl.Allow(ctx, "user-a", limit, window)
		assert.False(t, allowed, "User A should be limited")

		// Test user 2 (Shard B) - should not be affected by User A
		allowed, _ = rl.Allow(ctx, "user-b", limit, window)
		assert.True(t, allowed, "User B should be allowed despite User A being limited")
	})
}

func TestInMemoryRateLimiter_Concurrency(t *testing.T) {
	rl := NewInMemoryRateLimiter()
	ctx := context.Background()
	limit := 100
	window := time.Minute
	identifier := "concurrent-user"

	t.Run("High contention on single key", func(t *testing.T) {
		var wg sync.WaitGroup
		reqCount := 200
		results := make(chan bool, reqCount)

		for i := 0; i < reqCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				allowed, _ := rl.Allow(ctx, identifier, limit, window)
				results <- allowed
			}()
		}

		wg.Wait()
		close(results)

		successes := 0
		for res := range results {
			if res {
				successes++
			}
		}

		assert.Equal(t, limit, successes, "Should allow exactly the limit under high contention")
	})
}

func TestInMemoryRateLimiter_Cleanup(t *testing.T) {
	rl := NewInMemoryRateLimiter()
	identifier := "cleanup-test"

	t.Run("Manual prune call", func(t *testing.T) {
		// Fill a shard with an expired item
		shard := rl.getShard(identifier)
		shard.mu.Lock()
		shard.requests[identifier] = &bucketInfo{
			resetAt: time.Now().Add(-1 * time.Second),
		}
		shard.mu.Unlock()

		assert.Len(t, shard.requests, 1)

		// Trigger prune
		shard.mu.Lock()
		rl.pruneShard(shard, time.Now())
		shard.mu.Unlock()

		assert.Len(t, shard.requests, 0, "Expired entry should be removed")
	})
}

func TestInMemoryRateLimiter_Capacity(t *testing.T) {
	rl := NewInMemoryRateLimiter()
	ctx := context.Background()

	t.Run("Shard capacity enforcement", func(t *testing.T) {
		// We use a specific shard for testing
		targetShard := rl.shards[0]

		// Artificially fill the shard to its limit
		targetShard.mu.Lock()
		for i := 0; i < MaxTrackedClientsPerShard; i++ {
			id := fmt.Sprintf("fill-%d", i)
			targetShard.requests[id] = &bucketInfo{
				resetAt: time.Now().Add(time.Hour),
			}
		}
		targetShard.mu.Unlock()

		// Attempting to add one more to a shard that is full of NON-EXPIRED items
		// We need to find an ID that hashes to shard 0
		var nextID string
		for i := 0; ; i++ {
			id := fmt.Sprintf("test-%d", i)
			if rl.getShard(id) == targetShard && targetShard.requests[id] == nil {
				nextID = id
				break
			}
		}

		allowed, err := rl.Allow(ctx, nextID, 5, time.Minute)
		assert.False(t, allowed)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "capacity exceeded")
	})
}

func TestRedisRateLimiter(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rl := NewRedisRateLimiter(db)
	ctx := context.Background()
	identifier := "127.0.0.1"
	key := "rl:" + identifier
	limit := 5
	window := time.Minute

	t.Run("Successful flow", func(t *testing.T) {
		mock.ExpectIncr(key).SetVal(1)
		mock.ExpectExpire(key, window).SetVal(true)

		allowed, err := rl.Allow(ctx, identifier, limit, window)
		assert.NoError(t, err)
		assert.True(t, allowed)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Rate limit exceeded", func(t *testing.T) {
		mock.ExpectIncr(key).SetVal(6)
		mock.ExpectExpire(key, window).SetVal(true)

		allowed, err := rl.Allow(ctx, identifier, limit, window)
		assert.NoError(t, err)
		assert.False(t, allowed)
	})
}
