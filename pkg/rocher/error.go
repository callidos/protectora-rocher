package rocher

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Erreurs de base - normalisées
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

// CommunicationError structure d'erreur avec contexte minimal
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

// NewCommunicationError crée une nouvelle erreur
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

// isSensitiveKey vérifie si une clé contient des informations sensibles
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
