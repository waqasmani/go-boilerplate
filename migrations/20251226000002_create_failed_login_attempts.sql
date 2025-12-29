-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_email_attempt_time (email, attempt_time),
    INDEX idx_ip_attempt_time (ip_address, attempt_time),
    CONSTRAINT fk_failed_login_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE failed_login_attempts;
-- +goose StatementEnd