package communication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	maxPlaintextSize = 10 * 1024 * 1024 // 10MB limite
	encKeySize       = 32
	encNonceSize     = 24
)

// EncryptNaClBox chiffre avec NaCl secretbox (XSalsa20 + Poly1305)
// Nom corrigé pour refléter l'algorithme réellement utilisé
func EncryptNaClBox(plaintext, masterKey []byte) (string, error) {
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
	defer secureZeroResistant(encKey)

	// Conversion en format NaCl
	var key [encKeySize]byte
	copy(key[:], encKey[:encKeySize])

	// Génération du nonce
	var nonce [encNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement avec NaCl secretbox
	encrypted := secretbox.Seal(nil, plaintext, &nonce, &key)

	// Format: version(1) + nonce + ciphertext
	result := make([]byte, 1+encNonceSize+len(encrypted))
	result[0] = 1 // Version
	copy(result[1:1+encNonceSize], nonce[:])
	copy(result[1+encNonceSize:], encrypted)

	encoded := base64.StdEncoding.EncodeToString(result)

	// Nettoyage sécurisé résistant aux optimisations
	secureZeroResistant(result)
	secureZeroResistant(key[:])
	secureZeroResistant(nonce[:])

	return encoded, nil
}

// DecryptNaClBox déchiffre avec NaCl secretbox
// Nom corrigé pour refléter l'algorithme réellement utilisé
func DecryptNaClBox(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
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
	defer secureZeroResistant(data)

	// Validation de la taille minimale (version + nonce + secretbox overhead minimum)
	if len(data) < 1+encNonceSize+secretbox.Overhead {
		return nil, ErrInvalidFormat
	}

	// Vérification de la version
	if data[0] != 1 {
		return nil, ErrInvalidFormat
	}

	// Dérivation de clé
	encKey, err := deriveEncryptionKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer secureZeroResistant(encKey)

	var key [encKeySize]byte
	copy(key[:], encKey[:encKeySize])

	// Extraction des composants
	var nonce [encNonceSize]byte
	copy(nonce[:], data[1:1+encNonceSize])
	ciphertext := data[1+encNonceSize:]

	// Déchiffrement avec NaCl secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, ErrDecryption
	}

	// Nettoyage sécurisé
	secureZeroResistant(key[:])
	secureZeroResistant(nonce[:])

	return plaintext, nil
}

// EncryptWithAdditionalData chiffre avec données additionnelles
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

	// Combiner plaintext et additional data pour NaCl
	combined := make([]byte, len(additionalData)+len(plaintext))
	copy(combined[:len(additionalData)], additionalData)
	copy(combined[len(additionalData):], plaintext)
	defer secureZeroResistant(combined)

	// Dérivation de clé avec contexte additional data
	encKey, err := deriveKeyWithContext(masterKey, "with-ad", encKeySize)
	if err != nil {
		return "", err
	}
	defer secureZeroResistant(encKey)

	var key [encKeySize]byte
	copy(key[:], encKey)

	// Génération du nonce
	var nonce [encNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement
	encrypted := secretbox.Seal(nil, combined, &nonce, &key)

	// Format: version(1) + ad_length(4) + nonce + ciphertext
	result := make([]byte, 1+4+encNonceSize+len(encrypted))
	result[0] = 2 // Version avec AD
	binary.BigEndian.PutUint32(result[1:5], uint32(len(additionalData)))
	copy(result[5:5+encNonceSize], nonce[:])
	copy(result[5+encNonceSize:], encrypted)

	encoded := base64.StdEncoding.EncodeToString(result)
	secureZeroResistant(result)
	secureZeroResistant(key[:])
	secureZeroResistant(nonce[:])

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
	defer secureZeroResistant(data)

	// Validation de la taille minimale
	if len(data) < 5+encNonceSize+secretbox.Overhead {
		return nil, ErrInvalidFormat
	}

	// Vérification de la version
	if data[0] != 2 {
		return nil, ErrInvalidFormat
	}

	// Extraction de la longueur des données additionnelles
	adLength := binary.BigEndian.Uint32(data[1:5])
	if adLength > 1024 {
		return nil, ErrInvalidFormat
	}

	// Dérivation de clé
	encKey, err := deriveKeyWithContext(masterKey, "with-ad", encKeySize)
	if err != nil {
		return nil, err
	}
	defer secureZeroResistant(encKey)

	var key [encKeySize]byte
	copy(key[:], encKey)

	// Extraction des composants
	var nonce [encNonceSize]byte
	copy(nonce[:], data[5:5+encNonceSize])
	ciphertext := data[5+encNonceSize:]

	// Déchiffrement
	combined, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, ErrDecryption
	}
	defer secureZeroResistant(combined)

	// Validation de la longueur
	if len(combined) < int(adLength) {
		return nil, ErrDecryption
	}

	// Vérification des données additionnelles
	actualAD := combined[:adLength]
	if !CompareConstantTime(actualAD, expectedAdditionalData) {
		return nil, ErrDecryption
	}

	// Extraction du plaintext
	plaintext := make([]byte, len(combined)-int(adLength))
	copy(plaintext, combined[adLength:])

	// Nettoyage sécurisé
	secureZeroResistant(key[:])
	secureZeroResistant(nonce[:])

	return plaintext, nil
}

// deriveEncryptionKey dérive une clé de chiffrement avec HKDF
func deriveEncryptionKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrInvalidKey
	}

	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-nacl-encryption-v2") // Nom corrigé

	h := hkdf.New(sha256.New, masterKey, salt, info)
	key := make([]byte, encKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	return key, nil
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
	defer secureZeroResistant(data)

	// Vérification de la taille minimale
	if len(data) < 1+encNonceSize+secretbox.Overhead {
		return ErrInvalidFormat
	}

	// Vérification de la version
	version := data[0]
	if version != 1 && version != 2 {
		return ErrInvalidFormat
	}

	// Validation spécifique selon la version
	if version == 2 {
		if len(data) < 5+encNonceSize+secretbox.Overhead {
			return ErrInvalidFormat
		}
		adLength := binary.BigEndian.Uint32(data[1:5])
		if adLength > 1024 {
			return ErrInvalidFormat
		}
	}

	return nil
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
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// secureZeroResistant efface de manière sécurisée un slice de bytes
// résistant aux optimisations du compilateur
func secureZeroResistant(data []byte) {
	if len(data) == 0 {
		return
	}

	// Écriture de motifs multiples pour empêcher la récupération
	patterns := []byte{0xFF, 0x00, 0xAA, 0x55, 0x33, 0xCC}
	for _, pattern := range patterns {
		for i := range data {
			data[i] = pattern
		}
		// Empêcher l'optimisation du compilateur
		runtime.KeepAlive(data)
	}

	// Nettoyage final
	for i := range data {
		data[i] = 0
	}
	// Garantir que les données restent "vivantes" jusqu'ici
	runtime.KeepAlive(data)
}

// Fonctions de compatibilité avec les anciens noms
// Deprecated: Utiliser EncryptNaClBox à la place
func EncryptAESGCM(plaintext, masterKey []byte) (string, error) {
	return EncryptNaClBox(plaintext, masterKey)
}

// Deprecated: Utiliser DecryptNaClBox à la place
func DecryptAESGCM(ciphertextBase64 string, masterKey []byte) ([]byte, error) {
	return DecryptNaClBox(ciphertextBase64, masterKey)
}

// secureZero fonction de compatibilité
// Deprecated: Utiliser secureZeroResistant à la place
func secureZero(data []byte) {
	secureZeroResistant(data)
}
