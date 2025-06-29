// error.go
package rocher

import (
	"errors"
	"fmt"
)

// Erreurs de base pour le système simplifié
var (
	// Erreurs de chiffrement
	ErrEncryption = errors.New("encryption failed")
	ErrDecryption = errors.New("decryption failed")
	ErrInvalidKey = errors.New("invalid key")

	// Erreurs de réseau
	ErrConnection = errors.New("connection error")
	ErrTimeout    = errors.New("timeout")

	// Erreurs de données
	ErrInvalidInput  = errors.New("invalid input")
	ErrInvalidFormat = errors.New("invalid format")
	ErrDataTooLarge  = errors.New("data too large")
	ErrEmptyInput    = errors.New("empty input")

	// Erreurs de traitement
	ErrProcessing     = errors.New("processing failed")
	ErrAuthentication = errors.New("authentication failed")
)

// RocherError structure d'erreur personnalisée
type RocherError struct {
	Code    string
	Message string
	Cause   error
}

func (e *RocherError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *RocherError) Unwrap() error {
	return e.Cause
}

// Codes d'erreur
const (
	ErrorCodeCrypto  = "CRYPTO"
	ErrorCodeNetwork = "NETWORK"
	ErrorCodeInput   = "INPUT"
	ErrorCodeProcess = "PROCESS"
)

// Fonctions de création d'erreurs typées
func NewCryptoError(message string, cause error) *RocherError {
	return &RocherError{
		Code:    ErrorCodeCrypto,
		Message: message,
		Cause:   cause,
	}
}

func NewNetworkError(message string, cause error) *RocherError {
	return &RocherError{
		Code:    ErrorCodeNetwork,
		Message: message,
		Cause:   cause,
	}
}

func NewInputError(message string, cause error) *RocherError {
	return &RocherError{
		Code:    ErrorCodeInput,
		Message: message,
		Cause:   cause,
	}
}

func NewProcessError(message string, cause error) *RocherError {
	return &RocherError{
		Code:    ErrorCodeProcess,
		Message: message,
		Cause:   cause,
	}
}

// Fonctions utilitaires pour vérifier les types d'erreurs
func IsCryptoError(err error) bool {
	if rocherErr, ok := err.(*RocherError); ok {
		return rocherErr.Code == ErrorCodeCrypto
	}
	return err == ErrEncryption || err == ErrDecryption || err == ErrInvalidKey
}

func IsNetworkError(err error) bool {
	if rocherErr, ok := err.(*RocherError); ok {
		return rocherErr.Code == ErrorCodeNetwork
	}
	return err == ErrConnection || err == ErrTimeout
}

func IsInputError(err error) bool {
	if rocherErr, ok := err.(*RocherError); ok {
		return rocherErr.Code == ErrorCodeInput
	}
	return err == ErrInvalidInput || err == ErrInvalidFormat || err == ErrDataTooLarge || err == ErrEmptyInput
}

func IsTemporaryError(err error) bool {
	return IsNetworkError(err) || err == ErrTimeout
}

// FormatUserError formate une erreur pour l'affichage utilisateur
func FormatUserError(err error) string {
	switch {
	case IsCryptoError(err):
		return "Erreur de sécurité"
	case IsNetworkError(err):
		return "Erreur de connexion"
	case IsInputError(err):
		return "Données invalides"
	case err == ErrTimeout:
		return "Délai d'attente dépassé"
	case err == ErrProcessing:
		return "Erreur de traitement"
	default:
		return "Erreur inconnue"
	}
}
