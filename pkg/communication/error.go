package communication

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Erreurs de base - normalisées pour éviter les oracles d'information
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

// ErrorSeverity définit la sévérité d'une erreur
type ErrorSeverity int

const (
	SeverityLow ErrorSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// CommunicationError structure d'erreur sécurisée avec contexte minimal
type CommunicationError struct {
	Code      string
	Message   string
	Cause     error
	Severity  ErrorSeverity
	Timestamp time.Time
	Context   map[string]interface{}
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

// GetSeverity retourne la sévérité de l'erreur de manière thread-safe
func (e *CommunicationError) GetSeverity() ErrorSeverity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Severity
}

// GetContext retourne une copie du contexte pour éviter les modifications concurrentes
func (e *CommunicationError) GetContext() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.Context == nil {
		return make(map[string]interface{})
	}

	// Copie pour éviter les modifications concurrentes
	result := make(map[string]interface{}, len(e.Context))
	for k, v := range e.Context {
		result[k] = v
	}
	return result
}

// WithContext ajoute du contexte de manière thread-safe
func (e *CommunicationError) WithContext(key string, value interface{}) *CommunicationError {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}

	// Filtrer les valeurs sensibles
	if !isSensitiveKey(key) && !containsSensitiveValue(value) {
		e.Context[key] = value
	}

	return e
}

// Codes d'erreur standardisés
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

// NewCommunicationError crée une nouvelle erreur avec validation
func NewCommunicationError(code, message string, cause error) *CommunicationError {
	severity := determineSeverity(code, cause)

	return &CommunicationError{
		Code:      code,
		Message:   sanitizeMessage(message),
		Cause:     cause,
		Severity:  severity,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}
}

// determineSeverity détermine automatiquement la sévérité
func determineSeverity(code string, cause error) ErrorSeverity {
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

// sanitizeMessage nettoie un message d'erreur
func sanitizeMessage(message string) string {
	if len(message) > 200 {
		message = message[:200] + "..."
	}
	return message
}

// isSensitiveKey vérifie si une clé de contexte est sensible
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

// containsSensitiveValue vérifie si une valeur contient des données sensibles
func containsSensitiveValue(value interface{}) bool {
	if str, ok := value.(string); ok {
		return len(str) > 32 && (isHexString(str) || isBase64String(str))
	}
	return false
}

// isHexString vérifie si une chaîne ressemble à de l'hexadécimal
func isHexString(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// isBase64String vérifie si une chaîne ressemble à du base64
func isBase64String(s string) bool {
	if len(s) < 16 {
		return false
	}
	validChars := 0
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			validChars++
		}
	}
	return float64(validChars)/float64(len(s)) > 0.8
}

// Fonctions helper pour créer des erreurs typées

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

// Fonctions utilitaires pour l'analyse d'erreurs

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

	// Détermination basique pour les erreurs standard
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

	// Vérification des erreurs standard
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

// WrapError encapsule une erreur existante
func WrapError(err error, code, message string) *CommunicationError {
	return NewCommunicationError(code, message, err)
}

// FormatUserError formate une erreur pour l'affichage utilisateur
func FormatUserError(err error) string {
	if commErr, ok := err.(*CommunicationError); ok {
		switch commErr.Code {
		case ErrorCodeInvalidInput:
			return "Les données fournies ne sont pas valides"
		case ErrorCodeCryptographicFail:
			return "Erreur de sécurité lors du traitement"
		case ErrorCodeNetworkError:
			return "Problème de connexion réseau"
		case ErrorCodeFileError:
			return "Erreur lors du traitement du fichier"
		case ErrorCodeAuthError:
			return "Erreur d'authentification"
		case ErrorCodeTimeout:
			return "L'opération a pris trop de temps"
		case ErrorCodeRateLimit:
			return "Trop de requêtes, veuillez patienter"
		case ErrorCodeResourceLimit:
			return "Ressources insuffisantes"
		case ErrorCodeProtocolError:
			return "Erreur de communication"
		default:
			return "Une erreur s'est produite"
		}
	}

	// Messages pour les erreurs standard
	switch err {
	case ErrEmptyInput, ErrInvalidInput:
		return "Données invalides"
	case ErrInvalidKey:
		return "Clé de sécurité invalide"
	case ErrInvalidFormat:
		return "Format incorrect"
	case ErrDataTooLarge:
		return "Données trop volumineuses"
	case ErrDecryption, ErrEncryption:
		return "Erreur de sécurité"
	case ErrFileNotFound:
		return "Fichier introuvable"
	case ErrFileCreation:
		return "Création de fichier impossible"
	case ErrCorruptedFile:
		return "Fichier corrompu"
	case ErrConnection:
		return "Erreur de connexion"
	case ErrTimeout:
		return "Délai d'attente dépassé"
	case ErrAuthentication:
		return "Échec d'authentification"
	case ErrProcessing:
		return "Erreur de traitement"
	default:
		return "Erreur inconnue"
	}
}

// ErrorHandler interface pour gérer les erreurs
type ErrorHandler interface {
	HandleError(err error, context map[string]interface{})
}

// SecureErrorHandler gestionnaire sécurisé qui filtre les informations sensibles
type SecureErrorHandler struct {
	mu sync.RWMutex
}

func (h *SecureErrorHandler) HandleError(err error, context map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Filtrer le contexte avant logging
	filteredContext := h.filterContext(context)

	// Log sécurisé (implémentation basique)
	severity := GetErrorSeverity(err)
	message := FormatUserError(err)

	logLevel := "INFO"
	switch severity {
	case SeverityCritical:
		logLevel = "CRITICAL"
	case SeverityHigh:
		logLevel = "ERROR"
	case SeverityMedium:
		logLevel = "WARNING"
	}

	fmt.Printf("[%s] %s - Context: %v\n", logLevel, message, filteredContext)
}

func (h *SecureErrorHandler) filterContext(context map[string]interface{}) map[string]interface{} {
	if context == nil {
		return nil
	}

	filtered := make(map[string]interface{})
	for k, v := range context {
		if !isSensitiveKey(k) && !containsSensitiveValue(v) {
			filtered[k] = v
		} else {
			filtered[k] = "[REDACTED]"
		}
	}
	return filtered
}

// Instance globale du gestionnaire d'erreur
var (
	globalErrorHandler ErrorHandler = &SecureErrorHandler{}
	handlerMu          sync.RWMutex
)

func SetGlobalErrorHandler(handler ErrorHandler) {
	handlerMu.Lock()
	defer handlerMu.Unlock()
	globalErrorHandler = handler
}

func GetGlobalErrorHandler() ErrorHandler {
	handlerMu.RLock()
	defer handlerMu.RUnlock()
	return globalErrorHandler
}

func HandleError(err error, context map[string]interface{}) {
	handler := GetGlobalErrorHandler()
	if handler != nil {
		handler.HandleError(err, context)
	}
}

// ErrorMetrics pour collecter des statistiques d'erreurs
type ErrorMetrics struct {
	mu         sync.RWMutex
	counts     map[string]int64
	lastErrors map[string]time.Time
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
	return result
}

func ResetErrorMetrics() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()

	globalMetrics.counts = make(map[string]int64)
	globalMetrics.lastErrors = make(map[string]time.Time)
}
