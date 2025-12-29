package errors

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/waqasmani/go-boilerplate/internal/infrastructure/observability"
	"go.uber.org/zap"
)

type DBErrorType string

const (
	ErrorTypeDeadlock            DBErrorType = "deadlock"
	ErrorTypeConnectionTimeout   DBErrorType = "connection_timeout"
	ErrorTypeConnectionRefused   DBErrorType = "connection_refused"
	ErrorTypeConstraintViolation DBErrorType = "constraint_violation"
	ErrorTypeDuplicateKey        DBErrorType = "duplicate_key"
	ErrorTypeForeignKeyViolation DBErrorType = "foreign_key_violation"
	ErrorTypeQueryTimeout        DBErrorType = "query_timeout"
	ErrorTypeUnknown             DBErrorType = "unknown"
)

type Classifyable interface {
	Classify() DBErrorType
	Error() string
}

type DBError struct {
	Original error
	Type     DBErrorType
	Context  map[string]interface{}
}

func (e *DBError) Error() string {
	return fmt.Sprintf("database error: %s (%s)", e.Type, e.Original.Error())
}

func (e *DBError) Classify() DBErrorType {
	return e.Type
}

func (e *DBError) Unwrap() error {
	return e.Original
}

func NewDBError(err error, errType DBErrorType, ctx map[string]interface{}) *DBError {
	return &DBError{
		Original: err,
		Type:     errType,
		Context:  ctx,
	}
}

func ClassifyError(err error) DBErrorType {
	if err == nil {
		return ""
	}

	// Check for context errors first
	if err == context.DeadlineExceeded {
		return ErrorTypeQueryTimeout
	}
	if err == context.Canceled {
		return ErrorTypeQueryTimeout
	}

	// Check for standard SQL errors
	if err == sql.ErrNoRows {
		return ErrorTypeUnknown
	}
	if err == sql.ErrConnDone {
		return ErrorTypeConnectionRefused
	}

	// Check for MySQL specific errors
	mysqlErr, ok := err.(*mysql.MySQLError)
	if !ok {
		return ErrorTypeUnknown
	}

	switch mysqlErr.Number {
	case 1213: // Deadlock
		return ErrorTypeDeadlock
	case 1205: // Lock wait timeout
		return ErrorTypeDeadlock
	case 2003, 2005: // Connection refused
		return ErrorTypeConnectionRefused
	case 2013: // Lost connection during query
		return ErrorTypeConnectionTimeout
	case 1062: // Duplicate key
		return ErrorTypeDuplicateKey
	case 1451, 1452: // Foreign key violation
		return ErrorTypeForeignKeyViolation
	case 1048, 1146: // Null value constraint, table not found
		return ErrorTypeConstraintViolation
	case 1206: // Lock table full
		return ErrorTypeDeadlock
	case 3024: // Query execution timeout
		return ErrorTypeQueryTimeout
	}

	return ErrorTypeUnknown
}

func IsTransientError(err error) bool {
	errType := ClassifyError(err)
	switch errType {
	case ErrorTypeDeadlock, ErrorTypeConnectionTimeout, ErrorTypeConnectionRefused, ErrorTypeQueryTimeout:
		return true
	default:
		return false
	}
}

func LogDBError(logger *observability.Logger, err error, operation, query string) {
	dbErr := &DBError{
		Original: err,
		Type:     ClassifyError(err),
		Context: map[string]interface{}{
			"operation": operation,
			"query":     query,
		},
	}

	fields := []zap.Field{
		logger.Field("error_type", dbErr.Type),
		logger.Field("original_error", dbErr.Original.Error()),
		logger.Field("operation", operation),
		logger.Field("query", query),
	}

	if dbErr.Type == ErrorTypeDeadlock || dbErr.Type == ErrorTypeQueryTimeout {
		logger.Warn(context.Background(), "Transient database error", fields...)
	} else {
		logger.Error(context.Background(), "Persistent database error", fields...)
	}
}
