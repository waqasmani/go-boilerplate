-- +goose Up
-- +goose StatementBegin

-- Shifts table: define working hours templates
CREATE TABLE IF NOT EXISTS shifts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    break_minutes INT UNSIGNED NOT NULL DEFAULT 30,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Employee shift assignments: assign users to shifts for date ranges
CREATE TABLE IF NOT EXISTS employee_shifts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    shift_id BIGINT UNSIGNED NOT NULL,
    effective_date DATE NOT NULL,
    end_date DATE NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_employee_shifts_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_employee_shifts_shift FOREIGN KEY (shift_id) REFERENCES shifts (id) ON DELETE RESTRICT,
    INDEX idx_user_date (user_id, effective_date),
    INDEX idx_shift_id (shift_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Attendance records: core check-in/out tracking
CREATE TABLE IF NOT EXISTS attendance_records (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    shift_id BIGINT UNSIGNED NULL,
    check_in_at TIMESTAMP NOT NULL,
    check_out_at TIMESTAMP NULL,
    duration_seconds INT UNSIGNED NULL,
    overtime_seconds INT UNSIGNED NULL DEFAULT 0,
    status ENUM('present', 'on_leave', 'absent', 'manual') NOT NULL DEFAULT 'present',
    check_in_lat DECIMAL(10, 8) NULL,
    check_in_lng DECIMAL(11, 8) NULL,
    check_out_lat DECIMAL(10, 8) NULL,
    check_out_lng DECIMAL(11, 8) NULL,
    client_check_in_at TIMESTAMP NULL,
    client_check_out_at TIMESTAMP NULL,
    is_late BOOLEAN NOT NULL DEFAULT FALSE,
    is_early_leave BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_attendance_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_attendance_shift FOREIGN KEY (shift_id) REFERENCES shifts (id) ON DELETE SET NULL,
    INDEX idx_user_checkin (user_id, check_in_at),
    INDEX idx_checkout_null (user_id, check_out_at),
    INDEX idx_status_date (status, check_in_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Holidays: public/company holidays
CREATE TABLE IF NOT EXISTS holidays (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    date DATE NOT NULL UNIQUE,
    is_paid BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_date (date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Time off requests: leave/vacation requests
CREATE TABLE IF NOT EXISTS time_off_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    leave_type ENUM('sick', 'vacation', 'personal', 'unpaid') NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    days_count DECIMAL(5, 2) NOT NULL,
    reason TEXT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    reviewed_by BIGINT UNSIGNED NULL,
    reviewed_at TIMESTAMP NULL,
    review_note TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_timeoff_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_timeoff_reviewer FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL,
    INDEX idx_user_status (user_id, status),
    INDEX idx_dates (start_date, end_date),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Attendance notes: manager annotations and corrections
CREATE TABLE IF NOT EXISTS attendance_notes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    attendance_id BIGINT UNSIGNED NOT NULL,
    added_by BIGINT UNSIGNED NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_notes_attendance FOREIGN KEY (attendance_id) REFERENCES attendance_records (id) ON DELETE CASCADE,
    CONSTRAINT fk_notes_user FOREIGN KEY (added_by) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_attendance_id (attendance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Attendance exceptions: flagged issues (late, early leave, etc)
CREATE TABLE IF NOT EXISTS attendance_exceptions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    attendance_id BIGINT UNSIGNED NOT NULL,
    exception_type ENUM('late_checkin', 'early_checkout', 'missing_checkout', 'overtime', 'unauthorized') NOT NULL,
    severity ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'warning',
    auto_flagged BOOLEAN NOT NULL DEFAULT TRUE,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_by BIGINT UNSIGNED NULL,
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_exceptions_attendance FOREIGN KEY (attendance_id) REFERENCES attendance_records (id) ON DELETE CASCADE,
    CONSTRAINT fk_exceptions_resolver FOREIGN KEY (resolved_by) REFERENCES users (id) ON DELETE SET NULL,
    INDEX idx_attendance_id (attendance_id),
    INDEX idx_resolved (resolved),
    INDEX idx_exception_type (exception_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Leave accruals: track leave balance per user
CREATE TABLE IF NOT EXISTS leave_accruals (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    leave_type ENUM('sick', 'vacation', 'personal') NOT NULL,
    accrued_days DECIMAL(6, 2) NOT NULL DEFAULT 0,
    used_days DECIMAL(6, 2) NOT NULL DEFAULT 0,
    carryover_days DECIMAL(6, 2) NOT NULL DEFAULT 0,
    year INT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_accruals_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_type_year (user_id, leave_type, year),
    INDEX idx_user_year (user_id, year)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
-- Insert default shift
INSERT INTO shifts (name, start_time, end_time, break_minutes, is_active) 
VALUES ('Standard Shift', '09:00:00', '17:00:00', 30, TRUE);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS leave_accruals;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS attendance_exceptions;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS attendance_notes;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS time_off_requests;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS holidays;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS attendance_records;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS employee_shifts;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS shifts;
-- +goose StatementEnd