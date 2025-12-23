-- name: CreateUser :execresult
INSERT INTO users (email, password_hash, first_name, last_name, role, is_active)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetUserByID :one
SELECT id, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at
FROM users
WHERE id = ? AND is_active = TRUE
LIMIT 1;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at
FROM users
WHERE email = ? AND is_active = TRUE
LIMIT 1;

-- name: UpdateUser :exec
UPDATE users
SET first_name = ?, last_name = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListUsers :many
SELECT id, email, first_name, last_name, role, is_active, created_at, updated_at
FROM users
WHERE is_active = TRUE
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_active = TRUE;

-- name: DeactivateUser :exec
UPDATE users
SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;