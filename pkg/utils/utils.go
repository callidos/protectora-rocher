package utils

import (
	"encoding/base64"
)

// IsValidBase64 vérifie si une chaîne est du base64 valide
func IsValidBase64(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// ValidateStringLength valide qu'une chaîne respecte les limites de taille
func ValidateStringLength(s string, min, max int) bool {
	length := len(s)
	return length >= min && length <= max
}

// SanitizeString nettoie une chaîne en retirant les caractères dangereux
func SanitizeString(s string) string {
	if s == "" {
		return ""
	}

	// Simple nettoyage basique - peut être étendu selon les besoins
	result := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 32 && r <= 126 { // Caractères ASCII imprimables
			result = append(result, r)
		}
	}
	return string(result)
}
