package security

import "context"

type contextKey string

const (
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
	UserEmailKey contextKey = "user_email"
)

// ContextWithUserID adds the user ID to the context
func ContextWithUserID(ctx context.Context, userID uint64) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// ContextWithUserRole adds the user role to the context
func ContextWithUserRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, UserRoleKey, role)
}

// ContextWithUserEmail adds the user email to the context
func ContextWithUserEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, UserEmailKey, email)
}

// UserIDFromContext retrieves the user ID from context
func UserIDFromContext(ctx context.Context) (uint64, bool) {
	userID, ok := ctx.Value(UserIDKey).(uint64)
	return userID, ok
}

// UserRoleFromContext retrieves the user role from context
func UserRoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(UserRoleKey).(string)
	return role, ok
}

// UserEmailFromContext retrieves the user email from context
func UserEmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}
