-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    user_id,
    token_hash,
    csrf_hash,
    client_ip,
    user_agent,
    expires_at
) VALUES (
    ?, ?, ?, ?, ?, ?
);

-- name: GetRefreshToken :one
-- We query by the hash of the token provided by the user
SELECT id, user_id, token_hash, expires_at, revoked_at, created_at, client_ip, user_agent
FROM refresh_tokens
WHERE token_hash = ?
AND revoked_at IS NULL
LIMIT 1 FOR UPDATE;

-- name: ValidateRefreshToken :one
SELECT id, user_id, token_hash, csrf_hash, expires_at, revoked_at, created_at, client_ip, user_agent
FROM refresh_tokens
WHERE token_hash = ?
AND csrf_hash = ?
AND expires_at > NOW()
LIMIT 1 FOR UPDATE;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens 
SET revoked_at = CURRENT_TIMESTAMP 
WHERE token_hash = ?;

-- name: DeleteExpiredRefreshTokens :execresult
DELETE FROM refresh_tokens
WHERE expires_at < NOW()
   OR revoked_at < DATE_SUB(NOW(), INTERVAL 7 DAY)
LIMIT ?;

-- name: RecordFailedLoginAttempt :exec
INSERT INTO failed_login_attempts (user_id, email, ip_address, attempt_time)
VALUES (?, ?, ?, NOW());

-- name: GetFailedLoginAttempts :many
SELECT id, user_id, email, ip_address, attempt_time
FROM failed_login_attempts
WHERE email = ?
AND attempt_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)
ORDER BY attempt_time DESC;

-- name: ClearFailedLoginAttempts :exec
DELETE FROM failed_login_attempts
WHERE email = ?;

-- name: CleanupOldFailedLoginAttempts :execresult
DELETE FROM failed_login_attempts
WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)
LIMIT ?;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens 
SET revoked_at = CURRENT_TIMESTAMP 
WHERE user_id = ? AND revoked_at IS NULL;