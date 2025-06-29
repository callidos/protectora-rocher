package rocher

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
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

// padPKCS7 applies PKCS#7 padding
func padPKCS7(data []byte, blockSize int) []byte {
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

// unpadPKCS7 removes PKCS#7 padding
func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
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

// Alias pour compatibilité avec le reste du code
func secureZeroResistant(data []byte) {
	secureZeroMemory(data)
}
