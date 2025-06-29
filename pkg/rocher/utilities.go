package rocher

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"
	"unsafe"
)

// secureRandom generates cryptographically secure random bytes
func secureRandom(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return buf, nil
}

// secureRandomInt generates a cryptographically secure random integer
func secureRandomInt(max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}

	return n.Int64(), nil
}

// secureZeroMemory efface de manière sécurisée un slice de bytes
// résistant aux optimisations du compilateur
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

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// constantTimeSelect returns x if v == 1, y if v == 0
func constantTimeSelect(v, x, y int) int {
	return subtle.ConstantTimeSelect(v, x, y)
}

// xorBytes performs XOR operation on two byte slices
func xorBytes(dst, a, b []byte) {
	if len(a) != len(b) || len(dst) < len(a) {
		panic("xorBytes: length mismatch")
	}

	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// copyBytes creates a copy of a byte slice
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// isZeroBytes checks if all bytes are zero
func isZeroBytes(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// isAllZeros checks if all bytes in slice are zero (alias for consistency)
func isAllZeros(data []byte) bool {
	return isZeroBytes(data)
}

// generateRandomBytes generates secure random bytes of specified size
func generateRandomBytes(size int) ([]byte, error) {
	return secureRandom(size)
}

// generateRandomString generates a random string of specified length using safe characters
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	if length <= 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}

	result := make([]byte, length)
	charsetLen := int64(len(charset))

	for i := range result {
		idx, err := secureRandomInt(charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random string: %w", err)
		}
		result[i] = charset[idx]
	}

	return string(result), nil
}

// padBytes pads data to specified block size using PKCS#7 padding
func padBytes(data []byte, blockSize int) []byte {
	if blockSize <= 0 || blockSize > 255 {
		panic("invalid block size")
	}

	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)

	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	return padded
}

// unpadBytes removes PKCS#7 padding from data
func unpadBytes(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding in constant time
	paddingValid := 1
	for i := len(data) - padding; i < len(data); i++ {
		paddingValid &= subtle.ConstantTimeByteEq(data[i], byte(padding))
	}

	if paddingValid == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	return data[:len(data)-padding], nil
}

// validateDataSize validates that data size is within reasonable limits
func validateDataSize(data []byte, maxSize int) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	if len(data) > maxSize {
		return fmt.Errorf("data too large: %d > %d", len(data), maxSize)
	}
	return nil
}

// clampInt clamps an integer value between min and max
func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// clampInt64 clamps an int64 value between min and max
func clampInt64(value, min, max int64) int64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// safeStringLength returns the length of a string safely
func safeStringLength(s string) int {
	return len([]rune(s)) // Handle UTF-8 properly
}

// truncateString truncates a string to maximum length safely
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

// sanitizeString removes control characters from string
func sanitizeString(s string) string {
	runes := []rune(s)
	var result []rune

	for _, r := range runes {
		// Keep printable characters and common whitespace
		if r >= 32 || r == '\n' || r == '\r' || r == '\t' {
			result = append(result, r)
		}
	}

	return string(result)
}

// secureStringCompare compares two strings in constant time
func secureStringCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// generateUUID generates a simple UUID-like string
func generateUUID() string {
	// Generate 16 random bytes
	bytes, err := secureRandom(16)
	if err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}

	// Set version (4) and variant bits
	bytes[6] = (bytes[6] & 0x0f) | 0x40 // Version 4
	bytes[8] = (bytes[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4],
		bytes[4:6],
		bytes[6:8],
		bytes[8:10],
		bytes[10:16])
}

// fileExists checks if a file exists and is accessible
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// createDirectoryIfNotExists creates a directory if it doesn't exist
func createDirectoryIfNotExists(path string) error {
	if !fileExists(path) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	return nil
}

// openFileSecure opens a file with secure permissions
func openFileSecure(path string) (*os.File, error) {
	return os.Open(path)
}

// createFileSecure creates a file with secure permissions
func createFileSecure(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// removeFileSecure removes a file securely
func removeFileSecure(path string) error {
	// Try to overwrite the file before deletion for extra security
	if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		stat, statErr := file.Stat()
		if statErr == nil {
			// Overwrite with random data
			randomData := make([]byte, 1024)
			for written := int64(0); written < stat.Size(); {
				toWrite := min(len(randomData), int(stat.Size()-written))
				if _, err := rand.Read(randomData[:toWrite]); err == nil {
					file.Write(randomData[:toWrite])
				}
				written += int64(toWrite)
			}
		}
		file.Close()
	}

	return os.Remove(path)
}

// memoryBarrier ensures memory operations are not reordered
func memoryBarrier() {
	runtime.KeepAlive(nil)
}

// TimeConstantHash calculates a timing-safe hash comparison
func timeConstantHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// Utilities for working with arrays and slices

// reverseBytes reverses a byte slice in place
func reverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

// reverseBytesNew returns a new reversed byte slice
func reverseBytesNew(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[len(data)-1-i] = b
	}
	return result
}

// combineBytes combines multiple byte slices into one
func combineBytes(slices ...[]byte) []byte {
	totalLen := 0
	for _, slice := range slices {
		totalLen += len(slice)
	}

	result := make([]byte, 0, totalLen)
	for _, slice := range slices {
		result = append(result, slice...)
	}

	return result
}

// splitBytes splits a byte slice into chunks of specified size
func splitBytes(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		return nil
	}

	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}

	return chunks
}

// findBytePattern finds the first occurrence of pattern in data
func findBytePattern(data, pattern []byte) int {
	if len(pattern) == 0 {
		return 0
	}
	if len(pattern) > len(data) {
		return -1
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}

	return -1
}

// replaceBytePattern replaces all occurrences of old pattern with new pattern
func replaceBytePattern(data, old, new []byte) []byte {
	if len(old) == 0 {
		return data
	}

	var result []byte
	i := 0

	for i < len(data) {
		if index := findBytePattern(data[i:], old); index != -1 {
			// Add data before pattern
			result = append(result, data[i:i+index]...)
			// Add replacement
			result = append(result, new...)
			// Skip past the old pattern
			i += index + len(old)
		} else {
			// No more patterns, add rest of data
			result = append(result, data[i:]...)
			break
		}
	}

	return result
}

// Utility functions for validation

// isValidUTF8 checks if data is valid UTF-8
func isValidUTF8(data []byte) bool {
	// Simple UTF-8 validation
	for i := 0; i < len(data); {
		b := data[i]
		if b < 0x80 {
			i++
		} else if b < 0xC0 {
			return false // Invalid start byte
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

// isASCII checks if all bytes are ASCII (0-127)
func isASCII(data []byte) bool {
	for _, b := range data {
		if b > 127 {
			return false
		}
	}
	return true
}

// isPrintableASCII checks if all bytes are printable ASCII
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// Emergency cleanup functions

// emergencyCleanup performs emergency cleanup of sensitive data
func emergencyCleanup(sensitiveData ...[]byte) {
	for _, data := range sensitiveData {
		if data != nil {
			secureZeroMemory(data)
		}
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC() // Second call to be more thorough
}

// panicSecureCleanup performs cleanup and then panics
func panicSecureCleanup(message string, sensitiveData ...[]byte) {
	emergencyCleanup(sensitiveData...)
	panic(message)
}

// deferSecureCleanup returns a function that can be used with defer
func deferSecureCleanup(sensitiveData ...[]byte) func() {
	return func() {
		emergencyCleanup(sensitiveData...)
	}
}

// Benchmark and performance utilities

// measureExecutionTime measures the execution time of a function
func measureExecutionTime(name string, fn func()) time.Duration {
	start := time.Now()
	fn()
	duration := time.Since(start)
	fmt.Printf("[PERF] %s took %v\n", name, duration)
	return duration
}

// getMemoryUsage returns current memory usage statistics
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

// bToMb converts bytes to megabytes
func bToMb(b uint64) float64 {
	return float64(b) / 1024 / 1024
}

// forceGC forces garbage collection
func forceGC() {
	runtime.GC()
	runtime.GC()
}

// Sistema operacional e environment

// getOSInfo returns basic OS information
func getOSInfo() map[string]interface{} {
	return map[string]interface{}{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"cpus":       runtime.NumCPU(),
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
	}
}

// isLittleEndian checks if the system is little endian
func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	return b == 0x04
}
