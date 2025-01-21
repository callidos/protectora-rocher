package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

var sharedKey = []byte("thisisaverysecurekeythisisaverysecurekey")

func EncryptAudio(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("erreur de création du chiffrement AES: %v", err)
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("erreur de génération du nonce: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur de configuration AES-GCM: %v", err)
	}

	encrypted := aesGCM.Seal(nil, nonce, data, nil)
	return append(nonce, encrypted...), nil
}

func DecryptAudio(encryptedData []byte) ([]byte, error) {
	nonce, ciphertext := encryptedData[:12], encryptedData[12:]

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("erreur de création du chiffrement AES: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erreur de configuration AES-GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("erreur de déchiffrement AES: %v", err)
	}

	return plaintext, nil
}
