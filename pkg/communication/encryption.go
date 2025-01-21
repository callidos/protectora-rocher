package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

func DeriveKeys(masterKey []byte) ([]byte, []byte) {
	hash := sha256.Sum256(masterKey)
	encryptionKey := hash[:16]
	hmacKey := hash[16:]
	return encryptionKey, hmacKey
}

func EncryptAESGCM(plaintext []byte, masterKey []byte) (string, error) {
	encryptionKey, hmacKey := DeriveKeys(masterKey)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(plaintext)
	hmacValue := mac.Sum(nil)

	dataToEncrypt := append(hmacValue, plaintext...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("erreur de création du chiffrement AES: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("erreur de configuration AES-GCM: %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("erreur de génération du nonce: %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, dataToEncrypt, nil)
	finalMessage := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalMessage), nil
}

func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	encryptionKey, hmacKey := DeriveKeys(masterKey)

	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("erreur de décodage Base64: %v", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("erreur de création du chiffrement AES: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur de configuration AES-GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("données trop courtes")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]

	decryptedData, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("erreur de déchiffrement: %v", err)
	}

	expectedHMAC := decryptedData[:sha256.Size]
	plaintext := decryptedData[sha256.Size:]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(plaintext)
	calculatedHMAC := mac.Sum(nil)

	if !hmac.Equal(expectedHMAC, calculatedHMAC) {
		return nil, fmt.Errorf("échec de la vérification de l'intégrité du message")
	}

	return plaintext, nil
}

func GenerateHMAC(message string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
