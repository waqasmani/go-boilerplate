-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    user_id,
    token_hash,
    expires_at
) VALUES (
    ?, ?, ?
);

-- name: GetRefreshToken :one
-- We query by the hash of the token provided by the user
SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
FROM refresh_tokens
WHERE token_hash = ?
AND revoked_at IS NULL
LIMIT 1 FOR UPDATE;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens 
SET revoked_at = CURRENT_TIMESTAMP 
WHERE token_hash = ?;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < NOW()
   OR revoked_at < DATE_SUB(NOW(), INTERVAL 7 DAY);