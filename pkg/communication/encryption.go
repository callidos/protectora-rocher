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
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

func DeriveKeys(masterKey []byte) (encKey, hmacKey []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, errors.New("master key cannot be empty")
	}

	// CORRECTION: Ajouter un contexte versionnés pour la dérivation
	h := hkdf.New(sha256.New, masterKey, nil, []byte("protectora-rocher-keys-v1"))
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

// CORRECTION: Simplification - AES-GCM fournit déjà l'authentification,
// plus besoin d'HMAC externe (suppression de la redondance cryptographique)
func EncryptAESGCM(plaintext, masterKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("input data cannot be empty")
	}

	// Dériver uniquement la clé de chiffrement (pas besoin d'HMAC avec GCM)
	hkdf := hkdf.New(sha256.New, masterKey, nil, []byte("protectora-rocher-aes-v1"))
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, encryptionKey); err != nil {
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

	// GCM fournit déjà l'authentification, pas besoin d'HMAC externe
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	finalMessage := append(nonce, ciphertext...)

	// Nettoyage sécurisé de la clé
	MemzeroSecure(&encryptionKey)

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

	// Dériver la clé de chiffrement
	hkdf := hkdf.New(sha256.New, masterKey, nil, []byte("protectora-rocher-aes-v1"))
	encryptionKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, encryptionKey); err != nil {
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

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// GCM vérifie automatiquement l'authentification
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption or authentication failed: %w", err)
	}

	// Nettoyage sécurisé de la clé
	MemzeroSecure(&encryptionKey)

	return plaintext, nil
}

// CORRECTION: Garder cette fonction pour la compatibilité avec le protocole existant
// mais noter qu'elle est redondante avec GCM
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

// CORRECTION: Amélioration du nettoyage mémoire sécurisé
func MemzeroSecure(b *[]byte) {
	if b == nil || len(*b) == 0 {
		return
	}

	// Écriture de motifs différents pour rendre la récupération plus difficile
	for i := range *b {
		(*b)[i] = 0xFF
	}
	for i := range *b {
		(*b)[i] = 0x00
	}
	for i := range *b {
		(*b)[i] = 0xAA
	}
	for i := range *b {
		(*b)[i] = 0x00
	}

	// Forcer la synchronisation mémoire
	runtime.KeepAlive(b)

	// Tentative de forcer l'effacement au niveau CPU (best effort)
	if len(*b) > 0 {
		ptr := unsafe.Pointer(&(*b)[0])
		// Barrière mémoire pour empêcher l'optimisation
		runtime.KeepAlive(ptr)
	}
}
