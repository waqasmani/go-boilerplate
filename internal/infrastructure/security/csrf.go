package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CSRFManager defines the interface for CSRF token operations [cite: 35]
type CSRFManager interface {
	Generate(userID uint64) (string, error)
	Validate(token string, userID uint64) bool
	Delete(token string)
	Cleanup()
}

// --- In-Memory Implementation (Default) ---

type InMemoryCSRFManager struct {
	tokens map[string]*CSRFToken
	mu     sync.RWMutex
	ttl    time.Duration
}

type CSRFToken struct {
	Token     string
	UserID    uint64
	ExpiresAt time.Time
}

func NewInMemoryCSRFManager(ttl time.Duration) *InMemoryCSRFManager {
	manager := &InMemoryCSRFManager{
		tokens: make(map[string]*CSRFToken),
		ttl:    ttl,
	}
	go manager.cleanupLoop()
	return manager
}

func (m *InMemoryCSRFManager) Generate(userID uint64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token] = &CSRFToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	return token, nil
}

func (m *InMemoryCSRFManager) Validate(token string, userID uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	csrfToken, exists := m.tokens[token]
	if !exists {
		return false
	}
	if time.Now().After(csrfToken.ExpiresAt) {
		return false
	}
	return csrfToken.UserID == userID
}

func (m *InMemoryCSRFManager) Delete(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, token)
}

func (m *InMemoryCSRFManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for token, csrfToken := range m.tokens {
		if now.After(csrfToken.ExpiresAt) {
			delete(m.tokens, token)
		}
	}
}

func (m *InMemoryCSRFManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		m.Cleanup()
	}
}

// --- Redis Implementation (Production) ---

type RedisCSRFManager struct {
	client *redis.Client
	ttl    time.Duration
	prefix string
}

func NewRedisCSRFManager(client *redis.Client, ttl time.Duration) *RedisCSRFManager {
	return &RedisCSRFManager{
		client: client,
		ttl:    ttl,
		prefix: "csrf:",
	}
}

func (m *RedisCSRFManager) Generate(userID uint64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	key := m.prefix + token

	// Store userID in Redis with the token as key and set TTL
	if err := m.client.Set(context.Background(), key, userID, m.ttl).Err(); err != nil {
		return "", fmt.Errorf("redis set failed: %w", err)
	}

	return token, nil
}

func (m *RedisCSRFManager) Validate(token string, userID uint64) bool {
	key := m.prefix + token

	val, err := m.client.Get(context.Background(), key).Uint64()
	if err != nil {
		// Key does not exist (expired or never created) or connection error
		return false
	}

	return val == userID
}

func (m *RedisCSRFManager) Delete(token string) {
	key := m.prefix + token
	// Best-effort delete; error ignored as functionality isn't compromised if delete fails
	_ = m.client.Del(context.Background(), key)
}

func (m *RedisCSRFManager) Cleanup() {
	// No-op: Redis handles TTL expiration automatically
}
