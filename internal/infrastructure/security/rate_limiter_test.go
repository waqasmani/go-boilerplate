package security

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryRateLimiter(t *testing.T) {
	rl := NewInMemoryRateLimiter()
	ctx := context.Background()
	id := "user-1"
	limit := 2
	window := time.Second

	// 1. First request (Allowed)
	allowed, err := rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// 2. Second request (Allowed)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.True(t, allowed)

	// 3. Third request (Blocked)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.False(t, allowed)

	// 4. Wait for window expiration
	rl.mu.Lock()
	times := rl.requests[id]
	for i := range times.timestamps {
		times.timestamps[i] = times.timestamps[i].Add(-2 * time.Second)
	}
	rl.requests[id] = times
	rl.mu.Unlock()

	// 5. Request after expiration (Allowed)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestRedisRateLimiter_Allow(t *testing.T) {
	db, mock := redismock.NewClientMock()
	rl := NewRedisRateLimiter(db)
	ctx := context.Background()
	id := "127.0.0.1"
	key := "rl:" + id
	limit := 5
	window := time.Minute

	// Case 1: First Request (Incr returns 1) - Should set Expiry
	mock.ExpectIncr(key).SetVal(1)
	mock.ExpectExpire(key, window).SetVal(true)
	allowed, err := rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.True(t, allowed)
	assert.NoError(t, mock.ExpectationsWereMet())

	// Case 2: Subsequent Request (Incr returns 2) - Should still set Expiry
	mock.ExpectIncr(key).SetVal(2)
	mock.ExpectExpire(key, window).SetVal(true)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.True(t, allowed)
	assert.NoError(t, mock.ExpectationsWereMet())

	// Case 3: Limit Exceeded (Incr returns limit + 1)
	mock.ExpectIncr(key).SetVal(int64(limit + 1))
	mock.ExpectExpire(key, window).SetVal(true)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.NoError(t, err)
	assert.False(t, allowed)
	assert.NoError(t, mock.ExpectationsWereMet())

	// Case 4: Redis Error
	mock.ExpectIncr(key).SetErr(assert.AnError)
	allowed, err = rl.Allow(ctx, id, limit, window)
	assert.Error(t, err)
	assert.False(t, allowed)
	assert.NoError(t, mock.ExpectationsWereMet())
}
