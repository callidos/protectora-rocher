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
	resultChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	go func() {
		if len(plaintext) == 0 {
			errorChan <- fmt.Errorf("données d'entrée vides")
			return
		}

		encryptionKey, hmacKey, err := DeriveKeys(masterKey)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la dérivation de la clé : %v", err)
			return
		}

		h := hmac.New(sha256.New, hmacKey)
		h.Write(plaintext)
		hmacValue := h.Sum(nil)

		dataToEncrypt := append(hmacValue, plaintext...)

		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la création du chiffrement AES : %v", err)
			return
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la configuration AES-GCM : %v", err)
			return
		}

		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			errorChan <- fmt.Errorf("échec de la génération du nonce : %v", err)
			return
		}

		ciphertext := aesGCM.Seal(nil, nonce, dataToEncrypt, nil)
		finalMessage := append(nonce, ciphertext...)

		resultChan <- base64.StdEncoding.EncodeToString(finalMessage)
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return "", err
	}
}

func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		if len(ciphertextBase64) == 0 {
			errorChan <- fmt.Errorf("données chiffrées vides")
			return
		}

		encryptionKey, hmacKey, err := DeriveKeys(masterKey)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la dérivation de la clé : %v", err)
			return
		}

		data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
		if err != nil {
			errorChan <- fmt.Errorf("échec du décodage Base64 : %v", err)
			return
		}

		block, err := aes.NewCipher(encryptionKey)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la création du chiffrement AES : %v", err)
			return
		}

		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			errorChan <- fmt.Errorf("échec de la configuration AES-GCM : %v", err)
			return
		}

		nonceSize := aesGCM.NonceSize()
		if len(data) < nonceSize {
			errorChan <- fmt.Errorf("données trop courtes pour contenir un nonce valide")
			return
		}

		nonce, encryptedData := data[:nonceSize], data[nonceSize:]

		decryptedData, err := aesGCM.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			errorChan <- fmt.Errorf("échec du déchiffrement : %v", err)
			return
		}

		if len(decryptedData) < sha256.Size {
			errorChan <- fmt.Errorf("données déchiffrées trop courtes pour contenir un HMAC valide")
			return
		}

		expectedHMAC := decryptedData[:sha256.Size]
		plaintext := decryptedData[sha256.Size:]

		h := hmac.New(sha256.New, hmacKey)
		h.Write(plaintext)
		calculatedHMAC := h.Sum(nil)

		if !hmac.Equal(expectedHMAC, calculatedHMAC) {
			errorChan <- fmt.Errorf("échec de la vérification de l'intégrité du message")
			return
		}

		resultChan <- plaintext
	}()

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	}
}

func GenerateHMAC(message string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
