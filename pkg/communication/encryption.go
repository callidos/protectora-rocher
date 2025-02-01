package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

func DeriveKeys(masterKey []byte) (encKey, hmacKey []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("master key cannot be empty")
	}

	h := hkdf.New(sha256.New, masterKey, nil, nil)
	encKey = make([]byte, 32)
	if _, err := io.ReadFull(h, encKey); err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	hmacKey = make([]byte, 32)
	if _, err := io.ReadFull(h, hmacKey); err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return encKey, hmacKey, nil
}

func EncryptAESGCM(plaintext, masterKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("input data cannot be empty")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("AES cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM mode initialization failed: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	finalMessage := append(nonce, ciphertext...)

	mac := computeHMAC(finalMessage, hmacKey)
	finalMessage = append(finalMessage, mac...)

	return base64.StdEncoding.EncodeToString(finalMessage), nil
}

func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	if ciphertextBase64 == "" {
		return nil, errors.New("ciphertext cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, errors.New("invalid base64 encoding")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	if len(data) < sha256.Size {
		return nil, errors.New("invalid ciphertext length")
	}

	data, mac := data[:len(data)-sha256.Size], data[len(data)-sha256.Size:]
	if !hmac.Equal(computeHMAC(data, hmacKey), mac) {
		return nil, errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM mode initialization failed: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GenerateHMAC calcule un HMAC en utilisant SHA-256 et renvoie le résultat encodé en base64.
func GenerateHMAC(message string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func computeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func MemzeroSecure(b *[]byte) {
	// Pour chaque indice du slice, on force la mise à zéro
	for i := range *b {
		(*b)[i] = 0
	}
	// Éventuellement un keep-alive
	runtime.KeepAlive(b)
}
