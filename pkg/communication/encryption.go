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

func DeriveKeys(masterKey []byte) ([]byte, []byte, error) {
	if len(masterKey) == 0 {
		return nil, nil, fmt.Errorf("clé maître invalide")
	}

	hash := sha256.Sum256(masterKey)
	encryptionKey := hash[:16]
	hmacKey := hash[16:]

	return encryptionKey, hmacKey, nil
}

func EncryptAESGCM(plaintext []byte, masterKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("données d'entrée vides")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return "", fmt.Errorf("échec de la dérivation de la clé : %v", err)
	}

	h := hmac.New(sha256.New, hmacKey)
	h.Write(plaintext)
	hmacValue := h.Sum(nil)

	dataToEncrypt := append(hmacValue, plaintext...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("échec de la création du chiffrement AES : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("échec de la configuration AES-GCM : %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("échec de la génération du nonce : %v", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, dataToEncrypt, nil)
	finalMessage := append(nonce, ciphertext...)

	return base64.StdEncoding.EncodeToString(finalMessage), nil
}

func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	if len(ciphertextBase64) == 0 {
		return nil, fmt.Errorf("données chiffrées vides")
	}

	encryptionKey, hmacKey, err := DeriveKeys(masterKey)
	if err != nil {
		return nil, fmt.Errorf("échec de la dérivation de la clé : %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("échec du décodage Base64 : %v", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("échec de la création du chiffrement AES : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("échec de la configuration AES-GCM : %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("données trop courtes pour contenir un nonce valide")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]

	decryptedData, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("échec du déchiffrement : %v", err)
	}

	if len(decryptedData) < sha256.Size {
		return nil, fmt.Errorf("données déchiffrées trop courtes pour contenir un HMAC valide")
	}

	expectedHMAC := decryptedData[:sha256.Size]
	plaintext := decryptedData[sha256.Size:]

	h := hmac.New(sha256.New, hmacKey)
	h.Write(plaintext)
	calculatedHMAC := h.Sum(nil)

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
