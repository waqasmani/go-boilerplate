-- Attendance Records Queries

-- name: CreateAttendance :execresult
INSERT INTO attendance_records (
    user_id, shift_id, check_in_at, check_in_lat, check_in_lng, 
    client_check_in_at, is_late, status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAttendanceByID :one
SELECT id, user_id, shift_id, check_in_at, check_out_at, duration_seconds, 
    overtime_seconds, status, check_in_lat, check_in_lng, check_out_lat, check_out_lng,
    client_check_in_at, client_check_out_at, is_late, is_early_leave, created_at, updated_at
FROM attendance_records
WHERE id = ? LIMIT 1;

-- name: GetOpenAttendanceForUser :one
SELECT id, user_id, shift_id, check_in_at, check_out_at, duration_seconds,
    overtime_seconds, status, check_in_lat, check_in_lng, check_out_lat, check_out_lng,
    client_check_in_at, client_check_out_at, is_late, is_early_leave, created_at, updated_at
FROM attendance_records
WHERE user_id = ? AND check_out_at IS NULL
ORDER BY check_in_at DESC
LIMIT 1 FOR UPDATE;

-- name: CloseAttendance :exec
UPDATE attendance_records
SET check_out_at = ?, duration_seconds = ?, overtime_seconds = ?, 
    check_out_lat = ?, check_out_lng = ?, client_check_out_at = ?,
    is_early_leave = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListAttendance :many
SELECT id, user_id, shift_id, check_in_at, check_out_at, duration_seconds,
    overtime_seconds, status, is_late, is_early_leave, created_at, updated_at
FROM attendance_records
WHERE (? = 0 OR user_id = ?)
  AND (? IS NULL OR check_in_at >= ?)
  AND (? IS NULL OR check_in_at <= ?)
  AND (? = '' OR status = ?)
  AND (? = 0 OR shift_id = ?)
ORDER BY check_in_at DESC
LIMIT ? OFFSET ?;

-- name: CountAttendance :one
SELECT COUNT(*) FROM attendance_records
WHERE (? = 0 OR user_id = ?)
  AND (? IS NULL OR check_in_at >= ?)
  AND (? IS NULL OR check_in_at <= ?)
  AND (? = '' OR status = ?)
  AND (? = 0 OR shift_id = ?);

-- name: UpdateAttendanceManual :exec
UPDATE attendance_records
SET check_in_at = ?, check_out_at = ?, duration_seconds = ?,
    overtime_seconds = ?, status = 'manual', updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: AutoCloseStaleAttendance :execresult
UPDATE attendance_records
SET check_out_at = DATE_ADD(check_in_at, INTERVAL 24 HOUR),
    duration_seconds = 86400,
    status = 'manual',
    updated_at = CURRENT_TIMESTAMP
WHERE check_out_at IS NULL
  AND check_in_at < DATE_SUB(NOW(), INTERVAL ? HOUR);

-- Shift Queries

-- name: CreateShift :execresult
INSERT INTO shifts (name, start_time, end_time, break_minutes, is_active)
VALUES (?, ?, ?, ?, ?);

-- name: GetShift :one
SELECT id, name, start_time, end_time, break_minutes, is_active, created_at, updated_at
FROM shifts
WHERE id = ? LIMIT 1;

-- name: ListShifts :many
SELECT id, name, start_time, end_time, break_minutes, is_active, created_at, updated_at
FROM shifts
WHERE is_active = TRUE
ORDER BY name;

-- name: AssignShiftToEmployee :exec
INSERT INTO employee_shifts (user_id, shift_id, effective_date, end_date)
VALUES (?, ?, ?, ?);

-- name: GetEmployeeShiftForDate :one
SELECT es.id, es.user_id, es.shift_id, es.effective_date, es.end_date,
    s.name, s.start_time, s.end_time, s.break_minutes
FROM employee_shifts es
JOIN shifts s ON es.shift_id = s.id
WHERE es.user_id = ?
  AND es.effective_date <= ?
  AND (es.end_date IS NULL OR es.end_date >= ?)
ORDER BY es.effective_date DESC
LIMIT 1;

-- Time Off Requests

-- name: CreateTimeOffRequest :execresult
INSERT INTO time_off_requests (user_id, leave_type, start_date, end_date, days_count, reason, status)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetTimeOffByID :one
SELECT id, user_id, leave_type, start_date, end_date, days_count, reason,
    status, reviewed_by, reviewed_at, review_note, created_at, updated_at
FROM time_off_requests
WHERE id = ? LIMIT 1;

-- name: ListTimeOffForManager :many
SELECT tor.id, tor.user_id, tor.leave_type, tor.start_date, tor.end_date,
    tor.days_count, tor.reason, tor.status, tor.reviewed_by, tor.reviewed_at,
    tor.review_note, tor.created_at, tor.updated_at,
    u.first_name, u.last_name, u.email
FROM time_off_requests tor
JOIN users u ON tor.user_id = u.id
WHERE (? = '' OR tor.status = ?)
  AND (? IS NULL OR tor.start_date >= ?)
  AND (? IS NULL OR tor.end_date <= ?)
ORDER BY tor.created_at DESC
LIMIT ? OFFSET ?;

-- name: ApproveTimeOff :exec
UPDATE time_off_requests
SET status = 'approved', reviewed_by = ?, reviewed_at = NOW(), 
    review_note = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: RejectTimeOff :exec
UPDATE time_off_requests
SET status = 'rejected', reviewed_by = ?, reviewed_at = NOW(),
    review_note = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ListUserTimeOff :many
SELECT id, user_id, leave_type, start_date, end_date, days_count, reason,
    status, reviewed_by, reviewed_at, review_note, created_at, updated_at
FROM time_off_requests
WHERE user_id = ?
  AND (? = '' OR status = ?)
ORDER BY start_date DESC
LIMIT ? OFFSET ?;

-- Holidays

-- name: CreateHoliday :execresult
INSERT INTO holidays (name, date, is_paid, description)
VALUES (?, ?, ?, ?);

-- name: ListHolidays :many
SELECT id, name, date, is_paid, description, created_at, updated_at
FROM holidays
WHERE (? IS NULL OR date >= ?)
  AND (? IS NULL OR date <= ?)
ORDER BY date;

-- name: GetHolidayByDate :one
SELECT id, name, date, is_paid, description, created_at, updated_at
FROM holidays
WHERE date = ? LIMIT 1;

-- Attendance Notes

-- name: CreateAttendanceNote :exec
INSERT INTO attendance_notes (attendance_id, added_by, note)
VALUES (?, ?, ?);

-- name: ListAttendanceNotes :many
SELECT an.id, an.attendance_id, an.added_by, an.note, an.created_at,
    u.first_name, u.last_name
FROM attendance_notes an
JOIN users u ON an.added_by = u.id
WHERE an.attendance_id = ?
ORDER BY an.created_at DESC;

-- Exceptions

-- name: CreateAttendanceException :exec
INSERT INTO attendance_exceptions (attendance_id, exception_type, severity, auto_flagged)
VALUES (?, ?, ?, ?);

-- name: ListAttendanceExceptions :many
SELECT id, attendance_id, exception_type, severity, auto_flagged,
    resolved, resolved_by, resolved_at, created_at
FROM attendance_exceptions
WHERE attendance_id = ?
ORDER BY created_at DESC;

-- name: ResolveException :exec
UPDATE attendance_exceptions
SET resolved = TRUE, resolved_by = ?, resolved_at = NOW()
WHERE id = ?;

-- Leave Accruals

-- name: GetLeaveBalance :one
SELECT id, user_id, leave_type, accrued_days, used_days, carryover_days, year
FROM leave_accruals
WHERE user_id = ? AND leave_type = ? AND year = ?
LIMIT 1;

-- name: UpsertLeaveAccrual :exec
INSERT INTO leave_accruals (user_id, leave_type, accrued_days, used_days, carryover_days, year)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    accrued_days = VALUES(accrued_days),
    used_days = VALUES(used_days),
    carryover_days = VALUES(carryover_days),
    updated_at = CURRENT_TIMESTAMP;

-- Reports

-- name: DailySummary :many
SELECT DATE(check_in_at) as date,
    COUNT(*) as total_attendance,
    SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_count,
    SUM(CASE WHEN status = 'on_leave' THEN 1 ELSE 0 END) as on_leave_count,
    SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_count,
    SUM(CASE WHEN is_late = TRUE THEN 1 ELSE 0 END) as late_count,
    SUM(IFNULL(duration_seconds, 0)) as total_seconds,
    SUM(IFNULL(overtime_seconds, 0)) as total_overtime_seconds
FROM attendance_records
WHERE DATE(check_in_at) = ?
GROUP BY DATE(check_in_at);

-- name: EmployeeMonthlyAggregate :one
SELECT user_id,
    COUNT(*) as total_days,
    SUM(IFNULL(duration_seconds, 0)) as total_seconds,
    SUM(IFNULL(overtime_seconds, 0)) as total_overtime_seconds,
    SUM(CASE WHEN is_late = TRUE THEN 1 ELSE 0 END) as late_count,
    SUM(CASE WHEN is_early_leave = TRUE THEN 1 ELSE 0 END) as early_leave_count
FROM attendance_records
WHERE user_id = ?
  AND check_in_at >= ?
  AND check_in_at < ?
GROUP BY user_id;

-- name: ExportTimesheetForPeriod :many
SELECT ar.id, ar.user_id, u.email, u.first_name, u.last_name,
    DATE(ar.check_in_at) as work_date,
    ar.check_in_at, ar.check_out_at,
    ar.duration_seconds, ar.overtime_seconds,
    ar.shift_id, s.name as shift_name,
    ar.status, ar.is_late, ar.is_early_leave
FROM attendance_records ar
JOIN users u ON ar.user_id = u.id
LEFT JOIN shifts s ON ar.shift_id = s.id
WHERE ar.check_in_at >= ?
  AND ar.check_in_at < ?
  AND (? = 0 OR ar.user_id = ?)
ORDER BY ar.user_id, ar.check_in_at;

-- name: AcquireLock :exec
SELECT GET_LOCK(?, 10);

-- name: ReleaseLock :exec
SELECT RELEASE_LOCK(?);