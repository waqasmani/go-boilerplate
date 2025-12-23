package security

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCSRFManager_GenerateAndValidate(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Hour)
	userID := uint64(123)

	token, err := manager.Generate(userID)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	isValid := manager.Validate(token, userID)
	assert.True(t, isValid)
}

func TestCSRFManager_ValidateWrongUser(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Hour)
	userID := uint64(123)
	wrongUserID := uint64(456)

	token, err := manager.Generate(userID)
	assert.NoError(t, err)

	isValid := manager.Validate(token, wrongUserID)
	assert.False(t, isValid)
}

func TestCSRFManager_ValidateExpiredToken(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Millisecond * 10)
	userID := uint64(123)

	token, err := manager.Generate(userID)
	assert.NoError(t, err)

	time.Sleep(time.Millisecond * 20)

	isValid := manager.Validate(token, userID)
	assert.False(t, isValid)
}

func TestCSRFManager_ValidateNonExistentToken(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Hour)
	userID := uint64(123)

	isValid := manager.Validate("nonexistent-token", userID)
	assert.False(t, isValid)
}

func TestCSRFManager_Delete(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Hour)
	userID := uint64(123)

	token, err := manager.Generate(userID)
	assert.NoError(t, err)

	isValid := manager.Validate(token, userID)
	assert.True(t, isValid)

	manager.Delete(token)

	isValid = manager.Validate(token, userID)
	assert.False(t, isValid)
}

func TestCSRFManager_Cleanup(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Millisecond * 10)
	userID := uint64(123)

	token1, _ := manager.Generate(userID)
	
	time.Sleep(time.Millisecond * 20)
	
	token2, _ := manager.Generate(userID)

	manager.Cleanup()

	assert.False(t, manager.Validate(token1, userID))
	assert.True(t, manager.Validate(token2, userID))
}

func TestCSRFManager_ConcurrentAccess(t *testing.T) {
	manager := NewInMemoryCSRFManager(time.Hour)
	userID := uint64(123)

	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func() {
			token, err := manager.Generate(userID)
			assert.NoError(t, err)
			assert.True(t, manager.Validate(token, userID))
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}