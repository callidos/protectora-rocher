package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

const (
	maxPlaintextSize = 10 * 1024 * 1024 // 10MB limite
	minNonceSize     = 12               // Taille minimale de nonce pour AES-GCM
)

// Pool de ciphers pour éviter les allocations répétées
var (
	cipherPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32) // Buffer pour les clés
		},
	}
)

// NonceManager gère les nonces pour éviter les réutilisations
type NonceManager struct {
	mu    sync.Mutex
	used  map[string]bool
	count uint64
}

var globalNonceManager = &NonceManager{
	used: make(map[string]bool),
}

func (nm *NonceManager) generateNonce(size int) ([]byte, error) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		nonce := make([]byte, size)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("nonce generation failed: %w", err)
		}

		// Ajouter un compteur pour garantir l'unicité
		nm.count++
		binary.BigEndian.PutUint64(nonce[size-8:], nm.count)

		nonceKey := string(nonce)
		if !nm.used[nonceKey] {
			nm.used[nonceKey] = true

			// Nettoyage périodique pour éviter l'épuisement mémoire
			if len(nm.used) > 10000 {
				nm.cleanup()
			}

			return nonce, nil
		}
	}

	return nil, fmt.Errorf("failed to generate unique nonce after %d retries", maxRetries)
}

func (nm *NonceManager) cleanup() {
	// Conserver seulement les 5000 derniers nonces
	if len(nm.used) <= 5000 {
		return
	}

	newMap := make(map[string]bool, 5000)
	count := 0
	for k, v := range nm.used {
		if count >= 5000 {
			break
		}
		newMap[k] = v
		count++
	}
	nm.used = newMap
}

// EncryptAESGCM chiffre avec AES-GCM et protection contre la réutilisation de nonce
func EncryptAESGCM(plaintext, masterKey []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", ErrEmptyInput
	}
	if len(masterKey) == 0 {
		return "", ErrInvalidKey
	}
	if len(plaintext) > maxPlaintextSize {
		return "", ErrDataTooLarge
	}

	// Dérivation de clé sécurisée
	encKey, err := deriveEncryptionKey(masterKey)
	if err != nil {
		return "", err
	}
	defer secureZero(encKey)

	// Création du cipher AES-GCM
	aesGCM, err := createAESGCM(encKey)
	if err != nil {
		return "", err
	}

	// Génération du nonce unique et sécurisé
	nonce, err := globalNonceManager.generateNonce(aesGCM.NonceSize())
	if err != nil {
		return "", err
	}

	// Chiffrement avec authentification intégrée
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Format: version(1) + nonce + ciphertext
	result := make([]byte, 1+len(nonce)+len(ciphertext))
	result[0] = 1 // Version du format
	copy(result[1:1+len(nonce)], nonce)
	copy(result[1+len(nonce):], ciphertext)

	encoded := base64.StdEncoding.EncodeToString(result)

	// Nettoyage des données temporaires
	secureZero(result)
	secureZero(nonce)

	return encoded, nil
}

// DecryptAESGCM déchiffre et vérifie l'authentification avec validation renforcée
func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	if ciphertextBase64 == "" {
		return nil, ErrEmptyInput
	}
	if len(masterKey) == 0 {
		return nil, ErrInvalidKey
	}

	// Décodage base64 avec validation
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, ErrInvalidFormat
	}
	defer secureZero(data)

	// Validation de la taille minimale (version + nonce + tag GCM minimum)
	if len(data) < 1+minNonceSize+16 {
		return nil, ErrInvalidFormat
	}

	// Vérification de la version
	version := data[0]
	if version != 1 {
		return nil, ErrInvalidFormat
	}

	// Dérivation de clé
	encKey, err := deriveEncryptionKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer secureZero(encKey)

	// Création du cipher AES-GCM
	aesGCM, err := createAESGCM(encKey)
	if err != nil {
		return nil, err
	}

	// Validation de la taille avec la taille de nonce réelle
	nonceSize := aesGCM.NonceSize()
	if len(data) < 1+nonceSize+16 {
		return nil, ErrInvalidFormat
	}

	// Séparation des composants
	nonce := data[1 : 1+nonceSize]
	ciphertext := data[1+nonceSize:]

	// Déchiffrement avec vérification d'authentification automatique
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

// deriveEncryptionKey dérive une clé de chiffrement avec contexte renforcé
func deriveEncryptionKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrInvalidKey
	}

	// Utilisation d'HKDF avec un contexte spécifique et sel
	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-aes-encryption-v2")

	h := hkdf.New(sha256.New, masterKey, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return key, nil
}

// createAESGCM crée un cipher AES-GCM avec validation stricte
func createAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM mode initialization failed: %w", err)
	}

	return aesGCM, nil
}

// secureZero efface de manière sécurisée un slice de bytes
func secureZero(data []byte) {
	if len(data) == 0 {
		return
	}

	// Utilisation de subtle.ConstantTimeSelect pour empêcher l'optimisation
	for i := range data {
		data[i] = byte(subtle.ConstantTimeSelect(1, 0, int(data[i])))
	}

	// Motifs multiples pour empêcher la récupération
	patterns := []byte{0xFF, 0x00, 0xAA, 0x55, 0x33, 0xCC}
	for _, pattern := range patterns {
		for i := range data {
			data[i] = byte(subtle.ConstantTimeSelect(1, int(pattern), int(data[i])))
		}
		runtime.KeepAlive(data)
	}

	// Nettoyage final
	for i := range data {
		data[i] = 0
	}

	// Barrière mémoire finale
	if len(data) > 0 {
		ptr := unsafe.Pointer(&data[0])
		*(*byte)(ptr) = 0
		runtime.KeepAlive(ptr)
	}
}

// EncryptWithAdditionalData chiffre avec des données additionnelles
func EncryptWithAdditionalData(plaintext, masterKey, additionalData []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", ErrEmptyInput
	}
	if len(masterKey) == 0 {
		return "", ErrInvalidKey
	}
	if len(plaintext) > maxPlaintextSize {
		return "", ErrDataTooLarge
	}

	// Dérivation de clé sécurisée
	encKey, err := deriveEncryptionKey(masterKey)
	if err != nil {
		return "", err
	}
	defer secureZero(encKey)

	// Création du cipher AES-GCM
	aesGCM, err := createAESGCM(encKey)
	if err != nil {
		return "", err
	}

	// Génération du nonce unique
	nonce, err := globalNonceManager.generateNonce(aesGCM.NonceSize())
	if err != nil {
		return "", err
	}
	defer secureZero(nonce)

	// Chiffrement avec données additionnelles
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, additionalData)

	// Format: version(1) + ad_length(4) + ad + nonce + ciphertext
	result := make([]byte, 1+4+len(additionalData)+len(nonce)+len(ciphertext))
	result[0] = 2 // Version avec AD
	binary.BigEndian.PutUint32(result[1:5], uint32(len(additionalData)))
	copy(result[5:5+len(additionalData)], additionalData)
	copy(result[5+len(additionalData):5+len(additionalData)+len(nonce)], nonce)
	copy(result[5+len(additionalData)+len(nonce):], ciphertext)

	encoded := base64.StdEncoding.EncodeToString(result)
	secureZero(result)

	return encoded, nil
}

// DecryptWithAdditionalData déchiffre avec vérification des données additionnelles
func DecryptWithAdditionalData(ciphertextBase64 string, masterKey, expectedAdditionalData []byte) ([]byte, error) {
	if ciphertextBase64 == "" {
		return nil, ErrEmptyInput
	}
	if len(masterKey) == 0 {
		return nil, ErrInvalidKey
	}

	// Décodage base64
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, ErrInvalidFormat
	}
	defer secureZero(data)

	// Validation de la taille minimale
	if len(data) < 5+minNonceSize+16 {
		return nil, ErrInvalidFormat
	}

	// Vérification de la version
	version := data[0]
	if version != 2 {
		return nil, ErrInvalidFormat
	}

	// Extraction de la longueur des données additionnelles
	adLength := binary.BigEndian.Uint32(data[1:5])
	if adLength > 1024 { // Limite raisonnable pour les données additionnelles
		return nil, ErrInvalidFormat
	}

	// Validation de la taille avec les données additionnelles
	if len(data) < 5+int(adLength)+minNonceSize+16 {
		return nil, ErrInvalidFormat
	}

	// Extraction des données additionnelles
	additionalData := data[5 : 5+adLength]

	// Vérification que les données additionnelles correspondent
	if subtle.ConstantTimeCompare(additionalData, expectedAdditionalData) != 1 {
		return nil, ErrDecryption
	}

	// Dérivation de clé
	encKey, err := deriveEncryptionKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer secureZero(encKey)

	// Création du cipher AES-GCM
	aesGCM, err := createAESGCM(encKey)
	if err != nil {
		return nil, err
	}

	// Extraction du nonce et du ciphertext
	nonceStart := 5 + int(adLength)
	nonceSize := aesGCM.NonceSize()

	if len(data) < nonceStart+nonceSize+16 {
		return nil, ErrInvalidFormat
	}

	nonce := data[nonceStart : nonceStart+nonceSize]
	ciphertext := data[nonceStart+nonceSize:]

	// Déchiffrement avec vérification des données additionnelles
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

// ValidateEncryptedData valide qu'une chaîne est un ciphertext valide
func ValidateEncryptedData(ciphertextBase64 string) error {
	if ciphertextBase64 == "" {
		return ErrEmptyInput
	}

	// Vérification du format base64
	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return ErrInvalidFormat
	}
	defer secureZero(data)

	// Vérification de la taille minimale
	if len(data) < 1+minNonceSize+16 {
		return ErrInvalidFormat
	}

	// Vérification de la version
	version := data[0]
	if version != 1 && version != 2 {
		return ErrInvalidFormat
	}

	// Validation spécifique selon la version
	if version == 2 {
		// Version avec données additionnelles
		if len(data) < 5 {
			return ErrInvalidFormat
		}
		adLength := binary.BigEndian.Uint32(data[1:5])
		if len(data) < 5+int(adLength)+minNonceSize+16 {
			return ErrInvalidFormat
		}
	}

	return nil
}

// deriveKeyWithContext dérive une clé avec un contexte spécifique
func deriveKeyWithContext(masterKey []byte, context string, keySize int) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrInvalidKey
	}
	if keySize <= 0 || keySize > 64 {
		return nil, fmt.Errorf("invalid key size: %d", keySize)
	}

	salt := []byte("protectora-rocher-salt-v2")
	contextBytes := []byte("protectora-rocher-" + context + "-v2")
	h := hkdf.New(sha256.New, masterKey, salt, contextBytes)

	key := make([]byte, keySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return key, nil
}

// GenerateRandomKey génère une clé aléatoire sécurisée
func GenerateRandomKey(size int) ([]byte, error) {
	if size <= 0 || size > 64 {
		return nil, fmt.Errorf("invalid key size: %d", size)
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("random key generation failed: %w", err)
	}

	return key, nil
}

// CompareConstantTime compare deux slices de bytes de manière sécurisée
func CompareConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ResetNonceManager réinitialise le gestionnaire de nonces (pour les tests)
func ResetNonceManager() {
	globalNonceManager.mu.Lock()
	defer globalNonceManager.mu.Unlock()

	globalNonceManager.used = make(map[string]bool)
	globalNonceManager.count = 0
}
