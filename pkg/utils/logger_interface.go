package utils

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
)

// LoggerInterface définit les méthodes de logging sécurisées
type LoggerInterface interface {
	Info(message string, fields map[string]interface{})
	Warning(message string, fields map[string]interface{})
	Error(message string, fields map[string]interface{})
	Debug(message string, fields map[string]interface{})
}

// SecureLogger implémentation sécurisée qui évite l'exposition d'informations sensibles
type SecureLogger struct {
	mu                sync.RWMutex
	enabled           bool
	sensitiveKeys     map[string]bool
	sensitivePatterns []*regexp.Regexp
}

func NewSecureLogger() *SecureLogger {
	logger := &SecureLogger{
		enabled: true,
		sensitiveKeys: map[string]bool{
			// Clés cryptographiques
			"key": true, "keys": true, "masterkey": true, "sessionkey": true,
			"enckey": true, "deckey": true, "privatekey": true, "publickey": true,
			"dhkey": true, "ratchetkey": true, "chainkey": true, "messagekey": true,

			// Authentification
			"password": true, "passwd": true, "pwd": true, "secret": true,
			"token": true, "credential": true, "auth": true, "authorization": true,
			"bearer": true, "jwt": true, "oauth": true,

			// Données sensibles
			"private": true, "confidential": true, "sensitive": true,
			"hash": true, "signature": true, "nonce": true, "salt": true,
			"seed": true, "entropy": true,

			// Données personnelles
			"ssn": true, "social": true, "passport": true, "license": true,
			"phone": true, "email": true, "address": true,
		},
	}

	// Patterns pour détecter des données sensibles dans les valeurs
	logger.sensitivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|key)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)(bearer|auth)\s+[a-zA-Z0-9+/=]{20,}`),
		regexp.MustCompile(`[a-zA-Z0-9+/]{32,}={0,2}`), // Base64 suspect
		regexp.MustCompile(`[0-9a-fA-F]{32,}`),         // Hex suspect
		regexp.MustCompile(`\b[A-Za-z0-9]{20,}\b`),     // Chaînes longues suspectes
	}

	return logger
}

func (l *SecureLogger) logWithLevel(level, message string, fields map[string]interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if !l.enabled {
		return
	}

	// Nettoyer le message principal
	cleanMessage := l.sanitizeMessage(message)

	// Filtrer les champs sensibles
	filteredFields := l.filterSensitiveData(fields)

	if len(filteredFields) > 0 {
		log.Printf("[%s] %s - %v", level, cleanMessage, filteredFields)
	} else {
		log.Printf("[%s] %s", level, cleanMessage)
	}
}

func (l *SecureLogger) sanitizeMessage(message string) string {
	if message == "" {
		return message
	}

	// Appliquer les patterns pour masquer les données sensibles dans le message
	sanitized := message
	for _, pattern := range l.sensitivePatterns {
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			// Garder les premiers caractères pour le contexte
			if len(match) > 8 {
				return match[:4] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}

	return sanitized
}

func (l *SecureLogger) filterSensitiveData(fields map[string]interface{}) map[string]interface{} {
	if fields == nil {
		return nil
	}

	filtered := make(map[string]interface{})

	for k, v := range fields {
		key := strings.ToLower(k)

		// Vérifier si la clé est sensible
		if l.isSensitiveKey(key) {
			filtered[k] = "[REDACTED]"
			continue
		}

		// Vérifier si la valeur contient des données sensibles
		if strVal, ok := v.(string); ok {
			if l.containsSensitiveData(strVal) {
				filtered[k] = "[REDACTED]"
				continue
			}
		}

		// Traitement récursif pour les maps imbriquées
		if mapVal, ok := v.(map[string]interface{}); ok {
			filtered[k] = l.filterSensitiveData(mapVal)
			continue
		}

		// Traitement pour les slices
		if sliceVal, ok := v.([]interface{}); ok {
			filtered[k] = l.filterSensitiveSlice(sliceVal)
			continue
		}

		// Valeur considérée comme sûre
		filtered[k] = v
	}

	return filtered
}

func (l *SecureLogger) isSensitiveKey(key string) bool {
	// Vérification directe
	if l.sensitiveKeys[key] {
		return true
	}

	// Vérification des sous-chaînes sensibles
	for sensitiveKey := range l.sensitiveKeys {
		if strings.Contains(key, sensitiveKey) {
			return true
		}
	}

	return false
}

func (l *SecureLogger) containsSensitiveData(value string) bool {
	if len(value) == 0 {
		return false
	}

	// Vérifier avec les patterns
	for _, pattern := range l.sensitivePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	// Détection spécifique pour les données binaires encodées
	if len(value) > 32 {
		// Possible clé/token en base64
		if strings.HasSuffix(value, "=") || strings.HasSuffix(value, "==") {
			return true
		}

		// Possible données hexadécimales
		if regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(value) {
			return true
		}
	}

	return false
}

func (l *SecureLogger) filterSensitiveSlice(slice []interface{}) []interface{} {
	filtered := make([]interface{}, len(slice))

	for i, item := range slice {
		if strVal, ok := item.(string); ok {
			if l.containsSensitiveData(strVal) {
				filtered[i] = "[REDACTED]"
				continue
			}
		}

		if mapVal, ok := item.(map[string]interface{}); ok {
			filtered[i] = l.filterSensitiveData(mapVal)
			continue
		}

		filtered[i] = item
	}

	return filtered
}

func (l *SecureLogger) Info(message string, fields map[string]interface{}) {
	l.logWithLevel("INFO", message, fields)
}

func (l *SecureLogger) Warning(message string, fields map[string]interface{}) {
	l.logWithLevel("WARNING", message, fields)
}

func (l *SecureLogger) Error(message string, fields map[string]interface{}) {
	l.logWithLevel("ERROR", message, fields)
}

func (l *SecureLogger) Debug(message string, fields map[string]interface{}) {
	l.logWithLevel("DEBUG", message, fields)
}

func (l *SecureLogger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// AddSensitiveKey ajoute une clé à la liste des clés sensibles
func (l *SecureLogger) AddSensitiveKey(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sensitiveKeys[strings.ToLower(key)] = true
}

// AddSensitivePattern ajoute un pattern regex pour détecter des données sensibles
func (l *SecureLogger) AddSensitivePattern(pattern string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	l.sensitivePatterns = append(l.sensitivePatterns, regex)
	return nil
}

// DefaultLogger pour la rétrocompatibilité (mais moins sécurisé)
type DefaultLogger struct{}

func (l DefaultLogger) Info(message string, fields map[string]interface{}) {
	fmt.Printf("[INFO] %s\n", message)
}

func (l DefaultLogger) Warning(message string, fields map[string]interface{}) {
	fmt.Printf("[WARNING] %s\n", message)
}

func (l DefaultLogger) Error(message string, fields map[string]interface{}) {
	fmt.Printf("[ERROR] %s\n", message)
}

func (l DefaultLogger) Debug(message string, fields map[string]interface{}) {
	fmt.Printf("[DEBUG] %s\n", message)
}

// Instance globale thread-safe
var (
	globalLogger LoggerInterface
	loggerMu     sync.RWMutex
)

func init() {
	globalLogger = NewSecureLogger()
}

func GetLogger() LoggerInterface {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return globalLogger
}

func SetLogger(logger LoggerInterface) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	globalLogger = logger
}

// Logger pour la rétrocompatibilité
var Logger LoggerInterface = GetLogger()
