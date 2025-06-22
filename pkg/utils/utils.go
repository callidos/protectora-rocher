package utils

import (
	"encoding/base64"
	"runtime"
	"unsafe"
)

// IsValidBase64 vérifie si une chaîne est du base64 valide
func IsValidBase64(s string) bool {
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// SecureZero efface de manière sécurisée le contenu d'un slice
func SecureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Écriture de motifs multiples pour rendre la récupération difficile
	patterns := []byte{0xFF, 0x00, 0xAA, 0x55, 0x00}

	for _, pattern := range patterns {
		for i := range data {
			data[i] = pattern
		}
		runtime.KeepAlive(data) // Empêche l'optimisation
	}

	// Barrière mémoire finale
	if len(data) > 0 {
		ptr := unsafe.Pointer(&data[0])
		runtime.KeepAlive(ptr)
	}
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
