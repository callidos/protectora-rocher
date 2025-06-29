// utilities.go
package rocher

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"runtime"
	"time"
)

// secureZeroMemory efface de manière sécurisée un slice de bytes
func secureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Utiliser subtle.ConstantTimeCopy pour garantir que l'effacement n'est pas optimisé
	zeros := make([]byte, len(data))
	subtle.ConstantTimeCopy(1, data, zeros)

	// Double passage pour plus de sécurité
	for i := range data {
		data[i] = 0
	}

	// Garantir que les données restent "vivantes" jusqu'ici
	runtime.KeepAlive(data)
}

// ConstantTimeCompare effectue une comparaison en temps constant
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// isAllZeros vérifie si tous les bytes d'un slice sont à zéro
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// generateRandomBytes génère des bytes aléatoires sécurisés
func generateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return buf, nil
}

// generateUUID génère un UUID simple pour les messages
func generateUUID() string {
	// Générer 16 bytes aléatoires
	bytes, err := generateRandomBytes(16)
	if err != nil {
		// Fallback vers un ID basé sur le timestamp
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}

	// Définir les bits de version (4) et variant
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // Version 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4],
		bytes[4:6],
		bytes[6:8],
		bytes[8:10],
		bytes[10:16])
}

// clampInt restreint une valeur entière entre min et max
func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// min retourne le plus petit de deux entiers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max retourne le plus grand de deux entiers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// copyBytes crée une copie d'un slice de bytes
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// validateDataSize valide qu'un slice de données ne dépasse pas une taille maximale
func validateDataSize(data []byte, maxSize int) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	if len(data) > maxSize {
		return fmt.Errorf("data too large: %d > %d", len(data), maxSize)
	}
	return nil
}

// safeStringLength retourne la longueur d'une chaîne en gérant l'UTF-8
func safeStringLength(s string) int {
	return len([]rune(s))
}

// truncateString tronque une chaîne à une longueur maximale
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}

	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}

	return string(runes[:maxLen])
}

// TruncateString tronque une chaîne à une longueur maximale (fonction exportée)
func TruncateString(s string, maxLen int) string {
	return truncateString(s, maxLen)
}

// GenerateUUID génère un UUID simple pour les messages (fonction exportée)
func GenerateUUID() string {
	return generateUUID()
}

// sanitizeString supprime les caractères de contrôle d'une chaîne
func sanitizeString(s string) string {
	runes := []rune(s)
	var result []rune

	for _, r := range runes {
		// Conserver les caractères imprimables et les espaces communs
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			result = append(result, r)
		}
	}

	return string(result)
}

// measureExecutionTime mesure le temps d'exécution d'une fonction
func measureExecutionTime(name string, fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)
	fmt.Printf("[PERF] %s took %v\n", name, duration)
	return duration
}

// getMemoryUsage retourne des statistiques d'utilisation mémoire
func getMemoryUsage() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"alloc_mb":       bToMb(m.Alloc),
		"total_alloc_mb": bToMb(m.TotalAlloc),
		"sys_mb":         bToMb(m.Sys),
		"num_gc":         m.NumGC,
		"goroutines":     runtime.NumGoroutine(),
	}
}

// bToMb convertit des bytes en mégabytes
func bToMb(b uint64) float64 {
	return float64(b) / 1024 / 1024
}

// forceGC force le garbage collection
func forceGC() {
	runtime.GC()
	runtime.GC() // Double appel pour être plus approfondi
}

// getSystemInfo retourne des informations système de base
func getSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
	}
}

// emergencyCleanup effectue un nettoyage d'urgence des données sensibles
func emergencyCleanup(sensitiveData ...[]byte) {
	for _, data := range sensitiveData {
		if data != nil {
			secureZeroMemory(data)
		}
	}

	// Forcer le garbage collection
	runtime.GC()
	runtime.GC()
}

// deferCleanup retourne une fonction qui peut être utilisée avec defer
func deferCleanup(sensitiveData ...[]byte) func() {
	return func() {
		emergencyCleanup(sensitiveData...)
	}
}

// reverseBytes inverse un slice de bytes en place
func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

// xorBytes effectue une opération XOR entre deux slices de bytes
func xorBytes(dst, a, b []byte) {
	if len(a) != len(b) || len(dst) < len(a) {
		panic("xorBytes: length mismatch")
	}

	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}

// isValidUTF8 vérifie si les données sont en UTF-8 valide (version simplifiée)
func isValidUTF8(data []byte) bool {
	for i := 0; i < len(data); {
		b := data[i]
		if b < 0x80 {
			i++
		} else if b < 0xC0 {
			return false // Byte de continuation invalide
		} else if b < 0xE0 {
			if i+1 >= len(data) || data[i+1]&0xC0 != 0x80 {
				return false
			}
			i += 2
		} else if b < 0xF0 {
			if i+2 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 {
				return false
			}
			i += 3
		} else if b < 0xF8 {
			if i+3 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 || data[i+3]&0xC0 != 0x80 {
				return false
			}
			i += 4
		} else {
			return false
		}
	}
	return true
}

// isPrintableASCII vérifie si tous les bytes sont des caractères ASCII imprimables
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
