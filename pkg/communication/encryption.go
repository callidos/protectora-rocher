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

	"golang.org/x/crypto/hkdf"
)

func DeriveKeys(masterKey []byte) (encKey, hmacKey []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("master key cannot be empty")
	}

	h := hkdf.New(sha256.New, masterKey, nil, nil)
	encKey = make([]byte, 32) // AES-256
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
	if len(masterKey) == 0 {
		return "", errors.New("master key cannot be empty")
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	hmacValue := computeHMAC(plaintext, hmacKey)

	dataToEncrypt := append(hmacValue, plaintext...)

	ciphertext := aesGCM.Seal(nil, nonce, dataToEncrypt, nil)

	finalMessage := append(nonce, ciphertext...)

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

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]

	decryptedData, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	if len(decryptedData) < sha256.Size {
		return nil, errors.New("decrypted data too short to contain valid HMAC")
	}

	expectedHMAC, plaintext := decryptedData[:sha256.Size], decryptedData[sha256.Size:]

	if !hmac.Equal(expectedHMAC, computeHMAC(plaintext, hmacKey)) {
		return nil, errors.New("HMAC verification failed, message rejected")
	}

	return plaintext, nil
}

func GenerateHMAC(message string, key []byte) string {
	return base64.StdEncoding.EncodeToString(computeHMAC([]byte(message), key))
}

func computeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
