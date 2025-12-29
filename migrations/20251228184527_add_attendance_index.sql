-- +goose Up
CREATE INDEX idx_user_checkout_null ON attendance_records(user_id, check_out_at);

-- +goose Down  
DROP INDEX idx_user_checkout_null ON attendance_records;