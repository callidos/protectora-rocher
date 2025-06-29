package rocher

import (
	"errors"
	"fmt"
	"strings"
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
	ErrFileNotFound   = errors.New("file not found")
	ErrFileCreation   = errors.New("file creation failed")
	ErrCorruptedFile  = errors.New("file corrupted")
	ErrConnection     = errors.New("connection error")
	ErrTimeout        = errors.New("timeout")
	ErrInvalidInput   = errors.New("invalid input")
	ErrAuthentication = errors.New("authentication failed")
	ErrProcessing     = errors.New("processing failed")
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

// Standard error codes
const (
	ErrorCodeInvalidInput      = "INVALID_INPUT"
	ErrorCodeCryptographicFail = "CRYPTO_FAIL"
	ErrorCodeNetworkError      = "NETWORK_ERROR"
	ErrorCodeFileError         = "FILE_ERROR"
	ErrorCodeAuthError         = "AUTH_ERROR"
	ErrorCodeTimeout           = "TIMEOUT"
	ErrorCodeRateLimit         = "RATE_LIMIT"
	ErrorCodeResourceLimit     = "RESOURCE_LIMIT"
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
	case ErrorCodeProtocolError, ErrorCodeFileError:
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

func NewFileError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeFileError, message, cause)
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

func NewResourceLimitError(message string, cause error) *CommunicationError {
	return NewCommunicationError(ErrorCodeResourceLimit, message, cause)
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

	// Basic severity determination for standard errors
	switch err {
	case ErrAuthentication, ErrDecryption, ErrCorruptedFile:
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

// WrapError encapsulates an existing error
func WrapError(err error, code, message string) *CommunicationError {
	return NewCommunicationError(code, message, err)
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
		case ErrorCodeFileError:
			return "File processing error"
		case ErrorCodeAuthError:
			return "Authentication failed"
		case ErrorCodeTimeout:
			return "Operation timed out"
		case ErrorCodeRateLimit:
			return "Too many requests, please wait"
		case ErrorCodeResourceLimit:
			return "Insufficient resources"
		case ErrorCodeProtocolError:
			return "Communication error"
		default:
			return "An error occurred"
		}
	}

	// Messages for standard errors
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
	case ErrFileNotFound:
		return "File not found"
	case ErrFileCreation:
		return "Cannot create file"
	case ErrCorruptedFile:
		return "File corrupted"
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

// GetMostFrequentErrors retourne les erreurs les plus fréquentes
func GetMostFrequentErrors(limit int) []string {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()

	type errorCount struct {
		code  string
		count int64
	}

	var errors []errorCount
	for code, count := range globalMetrics.counts {
		errors = append(errors, errorCount{code: code, count: count})
	}

	// Tri simple par nombre d'occurrences (décroissant)
	for i := 0; i < len(errors); i++ {
		for j := i + 1; j < len(errors); j++ {
			if errors[j].count > errors[i].count {
				errors[i], errors[j] = errors[j], errors[i]
			}
		}
	}

	if limit > len(errors) {
		limit = len(errors)
	}

	result := make([]string, limit)
	for i := 0; i < limit; i++ {
		result[i] = errors[i].code
	}

	return result
}

// ErrorContext contient des informations contextuelles sur une erreur
type ErrorContext struct {
	Component string                 `json:"component"`
	Operation string                 `json:"operation"`
	UserID    string                 `json:"user_id,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ContextualError associe une erreur à son contexte
type ContextualError struct {
	Error   *CommunicationError `json:"error"`
	Context ErrorContext        `json:"context"`
}

// NewContextualError crée une erreur avec contexte
func NewContextualError(err *CommunicationError, component, operation string) *ContextualError {
	return &ContextualError{
		Error: err,
		Context: ErrorContext{
			Component: component,
			Operation: operation,
			Timestamp: time.Now(),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithUserID ajoute un ID utilisateur au contexte
func (ce *ContextualError) WithUserID(userID string) *ContextualError {
	ce.Context.UserID = userID
	return ce
}

// WithSessionID ajoute un ID de session au contexte
func (ce *ContextualError) WithSessionID(sessionID string) *ContextualError {
	ce.Context.SessionID = sessionID
	return ce
}

// WithMetadata ajoute des métadonnées au contexte
func (ce *ContextualError) WithMetadata(key string, value interface{}) *ContextualError {
	if ce.Context.Metadata == nil {
		ce.Context.Metadata = make(map[string]interface{})
	}
	ce.Context.Metadata[key] = value
	return ce
}

// String retourne une représentation string de l'erreur contextuelle
func (ce *ContextualError) String() string {
	return fmt.Sprintf("[%s:%s] %s", ce.Context.Component, ce.Context.Operation, ce.Error.Error())
}

// Log enregistre l'erreur contextuelle
func (ce *ContextualError) Log() {
	RecordError(ce.Error)
	fmt.Printf("[ERROR] %s\n", ce.String())
}

// IsSensitiveError vérifie si une erreur contient des informations sensibles
func IsSensitiveError(err error) bool {
	if commErr, ok := err.(*CommunicationError); ok {
		// Les erreurs cryptographiques peuvent contenir des infos sensibles
		return commErr.Code == ErrorCodeCryptographicFail
	}

	return false
}

// SanitizeError nettoie une erreur pour l'affichage public
func SanitizeError(err error) error {
	if IsSensitiveError(err) {
		return NewCommunicationError(ErrorCodeInternal, "Internal error", nil)
	}
	return err
}

// ValidationError pour les erreurs de validation spécifiques
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s", ve.Field, ve.Message)
}

// NewValidationError crée une nouvelle erreur de validation
func NewValidationError(field, rule, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Rule:    rule,
		Message: message,
	}
}

// MultiError pour regrouper plusieurs erreurs
type MultiError struct {
	Errors []error `json:"errors"`
}

func (me *MultiError) Error() string {
	if len(me.Errors) == 0 {
		return "no errors"
	}

	if len(me.Errors) == 1 {
		return me.Errors[0].Error()
	}

	var messages []string
	for _, err := range me.Errors {
		messages = append(messages, err.Error())
	}

	return fmt.Sprintf("multiple errors: %s", strings.Join(messages, "; "))
}

// AddError ajoute une erreur au MultiError
func (me *MultiError) AddError(err error) {
	if err != nil {
		me.Errors = append(me.Errors, err)
	}
}

// HasErrors vérifie s'il y a des erreurs
func (me *MultiError) HasErrors() bool {
	return len(me.Errors) > 0
}

// ToError convertit en error standard si il y a des erreurs
func (me *MultiError) ToError() error {
	if !me.HasErrors() {
		return nil
	}
	return me
}

// isSensitiveKey checks if a key contains sensitive information
func isSensitiveKey(key string) bool {
	sensitiveKeys := []string{
		"key", "password", "token", "secret", "auth", "credential",
		"private", "hash", "nonce", "salt", "seed", "entropy",
	}

	keyLower := strings.ToLower(key)
	for _, sensitive := range sensitiveKeys {
		if strings.Contains(keyLower, sensitive) {
			return true
		}
	}
	return false
}
