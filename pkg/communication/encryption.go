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
)

func DeriveKeys(masterKey []byte) ([]byte, []byte, error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("master key cannot be empty")
	}

	hash := sha256.Sum256(masterKey)
	return hash[:16], hash[16:], nil
}

func EncryptAESGCM(plaintext []byte, masterKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("input data cannot be empty")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	h := hmac.New(sha256.New, hmacKey)
	h.Write(plaintext)
	hmacValue := h.Sum(nil)

	dataToEncrypt := append(hmacValue, plaintext...)

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

	ciphertext := aesGCM.Seal(nil, nonce, dataToEncrypt, nil)
	finalMessage := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalMessage), nil
}

func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	if len(ciphertextBase64) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, errors.New("invalid base64 encoding")
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

	expectedHMAC := decryptedData[:sha256.Size]
	plaintext := decryptedData[sha256.Size:]

	h := hmac.New(sha256.New, hmacKey)
	h.Write(plaintext)
	calculatedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, calculatedHMAC) {
		return nil, errors.New("HMAC verification failed")
	}

	return plaintext, nil
}

func GenerateHMAC(message string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
