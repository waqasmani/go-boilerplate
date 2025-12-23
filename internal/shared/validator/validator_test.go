package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator(t *testing.T) {
	v := New()

	type User struct {
		Email string `validate:"required,email"`
		Age   int    `validate:"gte=18"`
	}

	// 1. Success
	u := User{Email: "test@test.com", Age: 20}
	assert.NoError(t, v.Validate(u))

	// 2. Failure
	badUser := User{Email: "invalid", Age: 10}
	err := v.Validate(badUser)
	assert.Error(t, err)

	// 3. Translation
	msgs := TranslateValidationErrors(err)
	assert.Len(t, msgs, 2)

	errorMap := make(map[string]string)
	for _, m := range msgs {
		errorMap[m.Field] = m.Message
	}

	assert.Contains(t, errorMap, "Age")
	assert.Contains(t, errorMap, "Email")
	assert.Equal(t, "Value must be greater than or equal to 18", errorMap["Age"])
}
