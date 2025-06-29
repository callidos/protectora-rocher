package rocher

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Base errors - normalized to prevent information leakage
var (
	ErrEmptyInput     = errors.New("invalid input")
	ErrInvalidKey     = errors.New("invalid key")
	ErrInvalidFormat  = errors.New("invalid format")
	ErrDataTooLarge   = errors.New("data too large")
	ErrDecryption     = errors.New("decryption failed")
	ErrEncryption     = errors.New("encryption failed")
	ErrConnection     = errors.New("connection error")
	ErrTimeout        = errors.New("timeout")
	ErrInvalidInput   = errors.New("invalid input")
	ErrAuthentication = errors.New("authentication failed")
	ErrProcessing     = errors.New("processing failed")
	ErrRateLimit      = errors.New("rate limit exceeded")
)

// ErrorSeverity defines error severity levels
type ErrorSeverity int

const (
	SeverityLow ErrorSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// CommunicationError provides structured error information
type CommunicationError struct {
	Code      string
	Message   string
	Cause     error
	Severity  ErrorSeverity
	Timestamp time.Time
	mu        sync.RWMutex
}

func (e *CommunicationError) Error() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *CommunicationError) Unwrap() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Cause
}

func (e *CommunicationError) GetSeverity() ErrorSeverity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Severity
}

// Error codes
const (
	ErrorCodeInvalidInput      = "INVALID_INPUT"
	ErrorCodeCryptographicFail = "CRYPTO_FAIL"
	ErrorCodeNetworkError      = "NETWORK_ERROR"
	ErrorCodeAuthError         = "AUTH_ERROR"
	ErrorCodeTimeout           = "TIMEOUT"
	ErrorCodeRateLimit         = "RATE_LIMIT"
	ErrorCodeProtocolError     = "PROTOCOL_ERROR"
	ErrorCodeInternal          = "INTERNAL_ERROR"
)

// NewCommunicationError creates a new structured error
func NewCommunicationError(code, message string, cause error) *CommunicationError {
	severity := determineSeverity(code)
	return &CommunicationError{
		Code:      code,
		Message:   sanitizeMessage(message),
		Cause:     cause,
		Severity:  severity,
		Timestamp: time.Now(),
	}
}

func determineSeverity(code string) ErrorSeverity {
	switch code {
	case ErrorCodeCryptographicFail, ErrorCodeAuthError:
		return SeverityCritical
	case ErrorCodeProtocolError:
		return SeverityHigh
	case ErrorCodeNetworkError, ErrorCodeTimeout, ErrorCodeRateLimit:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func sanitizeMessage(message string) string {
	if len(message) > 200 {
		message = message[:200] + "..."
	}
	return message
}

// Helper functions for creating typed errors
func NewInvalidInputError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeInvalidInput, message, cause)
}

func NewCryptographicError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeCryptographicFail, message, cause)
}

func NewNetworkError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeNetworkError, message, cause)
}

func NewAuthError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeAuthError, message, cause)
}

func NewTimeoutError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeTimeout, message, cause)
}

func NewRateLimitError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeRateLimit, message, cause)
}

func NewProtocolError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeProtocolError, message, cause)
}

// Error analysis utilities
func IsErrorCode(err error, code string) bool {
	if commErr, ok := err.(*CommunicationError); ok {
		return commErr.Code == code
	}
	return false
}

func GetErrorCode(err error) string {
	if commErr, ok := err.(*CommunicationError); ok {
		return commErr.Code
	}
	return ""
}

func GetErrorSeverity(err error) ErrorSeverity {
	if commErr, ok := err.(*CommunicationError); ok {
		return commErr.GetSeverity()
	}

	switch err {
	case ErrAuthentication, ErrDecryption:
		return SeverityCritical
	case ErrConnection, ErrTimeout:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func IsTemporaryError(err error) bool {
	if commErr, ok := err.(*CommunicationError); ok {
		switch commErr.Code {
		case ErrorCodeNetworkError, ErrorCodeTimeout, ErrorCodeRateLimit:
			return true
		default:
			return false
		}
	}

	switch err {
	case ErrConnection, ErrTimeout:
		return true
	default:
		return false
	}
}

func IsCriticalError(err error) bool {
	severity := GetErrorSeverity(err)
	return severity == SeverityCritical
}

// FormatUserError formats an error for user display (sanitized)
func FormatUserError(err error) string {
	if commErr, ok := err.(*CommunicationError); ok {
		switch commErr.Code {
		case ErrorCodeInvalidInput:
			return "Invalid data provided"
		case ErrorCodeCryptographicFail:
			return "Security error occurred"
		case ErrorCodeNetworkError:
			return "Network connection problem"
		case ErrorCodeAuthError:
			return "Authentication failed"
		case ErrorCodeTimeout:
			return "Operation timed out"
		case ErrorCodeRateLimit:
			return "Too many requests, please wait"
		case ErrorCodeProtocolError:
			return "Communication error"
		default:
			return "An error occurred"
		}
	}

	switch err {
	case ErrEmptyInput, ErrInvalidInput:
		return "Invalid data"
	case ErrInvalidKey:
		return "Invalid security key"
	case ErrInvalidFormat:
		return "Incorrect format"
	case ErrDataTooLarge:
		return "Data too large"
	case ErrDecryption, ErrEncryption:
		return "Security error"
	case ErrConnection:
		return "Connection error"
	case ErrTimeout:
		return "Timeout exceeded"
	case ErrAuthentication:
		return "Authentication failed"
	case ErrProcessing:
		return "Processing error"
	default:
		return "Unknown error"
	}
}

// ErrorMetrics for collecting error statistics
type ErrorMetrics struct {
	mu         sync.RWMutex
	counts     map[string]int64
	lastErrors map[string]time.Time
	totalCount int64
}

var globalMetrics = &ErrorMetrics{
	counts:     make(map[string]int64),
	lastErrors: make(map[string]time.Time),
}

func RecordError(err error) {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	code := GetErrorCode(err)
	if code == "" {
		code = "UNKNOWN"
	}

	globalMetrics.counts[code]++
	globalMetrics.lastErrors[code] = time.Now()
	globalMetrics.totalCount++
}

func GetErrorMetrics() map[string]interface{} {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()

	result := make(map[string]interface{})
	for code, count := range globalMetrics.counts {
		result[code] = map[string]interface{}{
			"count":     count,
			"last_seen": globalMetrics.lastErrors[code],
		}
	}

	result["total_errors"] = globalMetrics.totalCount
	result["error_types"] = len(globalMetrics.counts)
	return result
}

func ResetErrorMetrics() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	globalMetrics.counts = make(map[string]int64)
	globalMetrics.lastErrors = make(map[string]time.Time)
	globalMetrics.totalCount = 0
}

// ValidationError for specific validation errors
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s", ve.Field, ve.Message)
}

func NewValidationError(field, rule, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Rule:    rule,
		Message: message,
	}
}
