package utils

import (
	"regexp"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// LoggerInterface defines secure logging methods
type LoggerInterface interface {
	Info(message string, fields map[string]interface{})
	Warning(message string, fields map[string]interface{})
	Error(message string, fields map[string]interface{})
	Debug(message string, fields map[string]interface{})
}

// SecureLogrusHook implements logrus hook for sensitive data filtering
type SecureLogrusHook struct {
	sensitiveKeys     map[string]bool
	sensitivePatterns []*regexp.Regexp
	mu                sync.RWMutex
}

// NewSecureLogrusHook creates a new secure hook with default patterns
func NewSecureLogrusHook() *SecureLogrusHook {
	hook := &SecureLogrusHook{
		sensitiveKeys: make(map[string]bool),
		mu:            sync.RWMutex{},
	}

	// Default sensitive keys
	defaultKeys := []string{
		// Cryptographic keys
		"key", "keys", "masterkey", "sessionkey", "enckey", "deckey",
		"privatekey", "publickey", "dhkey", "ratchetkey", "chainkey", "messagekey",

		// Authentication
		"password", "passwd", "pwd", "secret", "token", "credential",
		"auth", "authorization", "bearer", "jwt", "oauth",

		// Sensitive data
		"private", "confidential", "sensitive", "hash", "signature",
		"nonce", "salt", "seed", "entropy",

		// Personal data
		"ssn", "social", "passport", "license", "phone", "email", "address",
	}

	for _, key := range defaultKeys {
		hook.sensitiveKeys[key] = true
	}

	// Default patterns for detecting sensitive data in values
	hook.sensitivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(bearer|auth)\s+[a-zA-Z0-9+/=]{20,}`),
		regexp.MustCompile(`[a-zA-Z0-9+/]{32,}={0,2}`), // Suspicious base64
		regexp.MustCompile(`[0-9a-fA-F]{32,}`),         // Suspicious hex
		regexp.MustCompile(`\b[A-Za-z0-9]{20,}\b`),     // Long suspicious strings
	}

	return hook
}

// Levels returns the levels this hook should fire for
func (h *SecureLogrusHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when a log entry is made
func (h *SecureLogrusHook) Fire(entry *logrus.Entry) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Filter sensitive data from log fields
	for key, value := range entry.Data {
		if h.isSensitiveKey(key) {
			entry.Data[key] = "[REDACTED]"
			continue
		}

		// Check string values for sensitive content
		if str, ok := value.(string); ok {
			if h.containsSensitiveData(str) {
				entry.Data[key] = "[REDACTED]"
				continue
			}
		}

		// Handle nested maps
		if mapVal, ok := value.(map[string]interface{}); ok {
			entry.Data[key] = h.filterSensitiveMap(mapVal)
			continue
		}

		// Handle slices
		if sliceVal, ok := value.([]interface{}); ok {
			entry.Data[key] = h.filterSensitiveSlice(sliceVal)
			continue
		}
	}

	// Filter sensitive data from the main message
	entry.Message = h.sanitizeMessage(entry.Message)

	return nil
}

// isSensitiveKey checks if a key contains sensitive information
func (h *SecureLogrusHook) isSensitiveKey(key string) bool {
	keyLower := strings.ToLower(key)

	// Direct check
	if h.sensitiveKeys[keyLower] {
		return true
	}

	// Check substrings
	for sensitiveKey := range h.sensitiveKeys {
		if strings.Contains(keyLower, sensitiveKey) {
			return true
		}
	}

	return false
}

// containsSensitiveData checks if value contains sensitive data
func (h *SecureLogrusHook) containsSensitiveData(value string) bool {
	if len(value) == 0 {
		return false
	}

	// Check with patterns
	for _, pattern := range h.sensitivePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	// Additional checks for encoded data
	if len(value) > 32 {
		// Possible base64 key/token
		if strings.HasSuffix(value, "=") || strings.HasSuffix(value, "==") {
			return true
		}

		// Possible hexadecimal data
		if regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(value) {
			return true
		}
	}

	return false
}

// sanitizeMessage sanitizes the main log message
func (h *SecureLogrusHook) sanitizeMessage(message string) string {
	if message == "" {
		return message
	}

	// Apply patterns to mask sensitive data in message
	sanitized := message
	for _, pattern := range h.sensitivePatterns {
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			// Keep first characters for context
			if len(match) > 8 {
				return match[:4] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}

	return sanitized
}

// filterSensitiveMap filters sensitive data from nested maps
func (h *SecureLogrusHook) filterSensitiveMap(data map[string]interface{}) map[string]interface{} {
	filtered := make(map[string]interface{})

	for k, v := range data {
		key := strings.ToLower(k)

		if h.isSensitiveKey(key) {
			filtered[k] = "[REDACTED]"
			continue
		}

		if strVal, ok := v.(string); ok {
			if h.containsSensitiveData(strVal) {
				filtered[k] = "[REDACTED]"
				continue
			}
		}

		// Recursive filtering for nested maps
		if mapVal, ok := v.(map[string]interface{}); ok {
			filtered[k] = h.filterSensitiveMap(mapVal)
			continue
		}

		// Recursive filtering for slices
		if sliceVal, ok := v.([]interface{}); ok {
			filtered[k] = h.filterSensitiveSlice(sliceVal)
			continue
		}

		filtered[k] = v
	}

	return filtered
}

// filterSensitiveSlice filters sensitive data from slices
func (h *SecureLogrusHook) filterSensitiveSlice(slice []interface{}) []interface{} {
	filtered := make([]interface{}, len(slice))

	for i, item := range slice {
		if strVal, ok := item.(string); ok {
			if h.containsSensitiveData(strVal) {
				filtered[i] = "[REDACTED]"
				continue
			}
		}

		if mapVal, ok := item.(map[string]interface{}); ok {
			filtered[i] = h.filterSensitiveMap(mapVal)
			continue
		}

		filtered[i] = item
	}

	return filtered
}

// AddSensitiveKey adds a key to the sensitive keys list
func (h *SecureLogrusHook) AddSensitiveKey(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sensitiveKeys[strings.ToLower(key)] = true
}

// AddSensitivePattern adds a regex pattern for detecting sensitive data
func (h *SecureLogrusHook) AddSensitivePattern(pattern string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	h.sensitivePatterns = append(h.sensitivePatterns, regex)
	return nil
}

// SecureLogger wraps logrus with security features
type SecureLogger struct {
	logger *logrus.Logger
	hook   *SecureLogrusHook
}

// NewSecureLogger creates a new secure logger with logrus
func NewSecureLogger() *SecureLogger {
	logger := logrus.New()
	hook := NewSecureLogrusHook()

	// Configure logger
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "@timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Add security hook
	logger.AddHook(hook)

	return &SecureLogger{
		logger: logger,
		hook:   hook,
	}
}

// NewSecureLoggerWithLevel creates a secure logger with specific level
func NewSecureLoggerWithLevel(level logrus.Level) *SecureLogger {
	sl := NewSecureLogger()
	sl.logger.SetLevel(level)
	return sl
}

// Info logs info level message
func (sl *SecureLogger) Info(message string, fields map[string]interface{}) {
	if fields != nil {
		sl.logger.WithFields(fields).Info(message)
	} else {
		sl.logger.Info(message)
	}
}

// Warning logs warning level message
func (sl *SecureLogger) Warning(message string, fields map[string]interface{}) {
	if fields != nil {
		sl.logger.WithFields(fields).Warn(message)
	} else {
		sl.logger.Warn(message)
	}
}

// Error logs error level message
func (sl *SecureLogger) Error(message string, fields map[string]interface{}) {
	if fields != nil {
		sl.logger.WithFields(fields).Error(message)
	} else {
		sl.logger.Error(message)
	}
}

// Debug logs debug level message
func (sl *SecureLogger) Debug(message string, fields map[string]interface{}) {
	if fields != nil {
		sl.logger.WithFields(fields).Debug(message)
	} else {
		sl.logger.Debug(message)
	}
}

// SetLevel sets the logging level
func (sl *SecureLogger) SetLevel(level logrus.Level) {
	sl.logger.SetLevel(level)
}

// AddSensitiveKey adds a sensitive key to filter
func (sl *SecureLogger) AddSensitiveKey(key string) {
	sl.hook.AddSensitiveKey(key)
}

// AddSensitivePattern adds a sensitive pattern to filter
func (sl *SecureLogger) AddSensitivePattern(pattern string) error {
	return sl.hook.AddSensitivePattern(pattern)
}

// GetLogrusLogger returns the underlying logrus logger
func (sl *SecureLogger) GetLogrusLogger() *logrus.Logger {
	return sl.logger
}

// LogrusAdapter adapts logrus logger to LoggerInterface
type LogrusAdapter struct {
	logger *logrus.Logger
}

// NewLogrusAdapter creates a new logrus adapter
func NewLogrusAdapter(logger *logrus.Logger) *LogrusAdapter {
	return &LogrusAdapter{logger: logger}
}

func (l *LogrusAdapter) Info(message string, fields map[string]interface{}) {
	if fields != nil {
		l.logger.WithFields(fields).Info(message)
	} else {
		l.logger.Info(message)
	}
}

func (l *LogrusAdapter) Warning(message string, fields map[string]interface{}) {
	if fields != nil {
		l.logger.WithFields(fields).Warn(message)
	} else {
		l.logger.Warn(message)
	}
}

func (l *LogrusAdapter) Error(message string, fields map[string]interface{}) {
	if fields != nil {
		l.logger.WithFields(fields).Error(message)
	} else {
		l.logger.Error(message)
	}
}

func (l *LogrusAdapter) Debug(message string, fields map[string]interface{}) {
	if fields != nil {
		l.logger.WithFields(fields).Debug(message)
	} else {
		l.logger.Debug(message)
	}
}

// DefaultLogger simple logger for backward compatibility
type DefaultLogger struct{}

func (l DefaultLogger) Info(message string, fields map[string]interface{}) {
	logrus.WithFields(fields).Info(message)
}

func (l DefaultLogger) Warning(message string, fields map[string]interface{}) {
	logrus.WithFields(fields).Warn(message)
}

func (l DefaultLogger) Error(message string, fields map[string]interface{}) {
	logrus.WithFields(fields).Error(message)
}

func (l DefaultLogger) Debug(message string, fields map[string]interface{}) {
	logrus.WithFields(fields).Debug(message)
}

// Global logger instance management
var (
	globalLogger LoggerInterface
	loggerMu     sync.RWMutex
)

func init() {
	globalLogger = NewSecureLogger()
}

// GetLogger returns the global logger instance
func GetLogger() LoggerInterface {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return globalLogger
}

// SetLogger sets the global logger instance
func SetLogger(logger LoggerInterface) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	globalLogger = logger
}

// SetLogLevel sets the log level for the global logger
func SetLogLevel(level string) error {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	if sl, ok := globalLogger.(*SecureLogger); ok {
		logrusLevel, err := logrus.ParseLevel(level)
		if err != nil {
			return err
		}
		sl.SetLevel(logrusLevel)
		return nil
	}

	return nil // Silently ignore for other logger types
}

// AddGlobalSensitiveKey adds a sensitive key to the global logger
func AddGlobalSensitiveKey(key string) {
	loggerMu.RLock()
	defer loggerMu.RUnlock()

	if sl, ok := globalLogger.(*SecureLogger); ok {
		sl.AddSensitiveKey(key)
	}
}

// AddGlobalSensitivePattern adds a sensitive pattern to the global logger
func AddGlobalSensitivePattern(pattern string) error {
	loggerMu.RLock()
	defer loggerMu.RUnlock()

	if sl, ok := globalLogger.(*SecureLogger); ok {
		return sl.AddSensitivePattern(pattern)
	}

	return nil // Silently ignore for other logger types
}

// GetGlobalLogrusLogger returns the underlying logrus logger if available
func GetGlobalLogrusLogger() *logrus.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()

	if sl, ok := globalLogger.(*SecureLogger); ok {
		return sl.GetLogrusLogger()
	}

	return nil
}

// Helper functions for common logging patterns

// LogWithError logs a message with an error field
func LogWithError(level string, message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["error"] = err.Error()

	logger := GetLogger()
	switch strings.ToLower(level) {
	case "info":
		logger.Info(message, fields)
	case "warning", "warn":
		logger.Warning(message, fields)
	case "error":
		logger.Error(message, fields)
	case "debug":
		logger.Debug(message, fields)
	default:
		logger.Info(message, fields)
	}
}

// LogOperation logs the start and end of an operation
func LogOperation(operationName string, fields map[string]interface{}) func(error) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["operation"] = operationName

	logger := GetLogger()
	logger.Info("Operation started", fields)

	return func(err error) {
		if err != nil {
			fields["error"] = err.Error()
			logger.Error("Operation failed", fields)
		} else {
			logger.Info("Operation completed", fields)
		}
	}
}
