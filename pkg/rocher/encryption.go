// encryption.go
package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	KeySize    = 32
	NonceSize  = 24
	MaxMsgSize = 1024 * 1024 // 1MB
)

var (
	ErrEmptyMessage     = errors.New("empty message")
	ErrMessageTooLarge  = errors.New("message too large")
	ErrInvalidNonce     = errors.New("invalid nonce")
	ErrDecryptionFailed = errors.New("decryption failed")
)

// Message représente un message chiffré avec ses métadonnées
type Message struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Data      []byte `json:"data"`  // Données chiffrées
	Nonce     []byte `json:"nonce"` // Nonce pour le chiffrement
}

// SecureChannel gère le chiffrement/déchiffrement des messages
type SecureChannel struct {
	encryptKey [KeySize]byte
	decryptKey [KeySize]byte
}

// NewSecureChannel crée un nouveau canal sécurisé à partir d'un secret partagé
func NewSecureChannel(sharedSecret []byte) (*SecureChannel, error) {
	if len(sharedSecret) < KeySize {
		return nil, errors.New("shared secret too short")
	}

	sc := &SecureChannel{}

	// Dérivation des clés de chiffrement et déchiffrement
	if err := sc.deriveKeys(sharedSecret); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return sc, nil
}

// deriveKeys dérive les clés de chiffrement/déchiffrement avec HKDF
func (sc *SecureChannel) deriveKeys(secret []byte) error {
	salt := []byte("rocher-simple-salt-v1")

	// Clé de chiffrement
	encInfo := []byte("rocher-encrypt-key-v1")
	hkdfEnc := hkdf.New(sha256.New, secret, salt, encInfo)
	if _, err := io.ReadFull(hkdfEnc, sc.encryptKey[:]); err != nil {
		return err
	}

	// Clé de déchiffrement (pour éviter la réutilisation de clé)
	decInfo := []byte("rocher-decrypt-key-v1")
	hkdfDec := hkdf.New(sha256.New, secret, salt, decInfo)
	if _, err := io.ReadFull(hkdfDec, sc.decryptKey[:]); err != nil {
		return err
	}

	// Vérifier que les clés ne sont pas nulles
	if isAllZeros(sc.encryptKey[:]) || isAllZeros(sc.decryptKey[:]) {
		return errors.New("derived keys are zero")
	}

	return nil
}

// EncryptMessage chiffre un message avec NaCl secretbox
func (sc *SecureChannel) EncryptMessage(plaintext []byte) (*Message, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyMessage
	}

	if len(plaintext) > MaxMsgSize {
		return nil, ErrMessageTooLarge
	}

	// Génération d'un nonce aléatoire
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement avec NaCl secretbox
	encrypted := secretbox.Seal(nil, plaintext, &nonce, &sc.encryptKey)

	message := &Message{
		ID:        generateMessageID(),
		Timestamp: time.Now().Unix(),
		Data:      encrypted,
		Nonce:     nonce[:],
	}

	return message, nil
}

// DecryptMessage déchiffre un message
func (sc *SecureChannel) DecryptMessage(msg *Message) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("nil message")
	}

	if len(msg.Data) == 0 {
		return nil, ErrEmptyMessage
	}

	if len(msg.Nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}

	// Copier le nonce dans un tableau de taille fixe
	var nonce [NonceSize]byte
	copy(nonce[:], msg.Nonce)

	// Déchiffrement avec NaCl secretbox
	plaintext, ok := secretbox.Open(nil, msg.Data, &nonce, &sc.decryptKey)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// SendMessage sérialise et envoie un message chiffré
func (sc *SecureChannel) SendMessage(plaintext []byte, writer io.Writer) error {
	// Chiffrer le message
	msg, err := sc.EncryptMessage(plaintext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Sérialiser en JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Envoyer la taille puis les données
	size := uint32(len(data))
	if err := binary.Write(writer, binary.BigEndian, size); err != nil {
		return fmt.Errorf("failed to write size: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// ReceiveMessage reçoit et déchiffre un message
func (sc *SecureChannel) ReceiveMessage(reader io.Reader) ([]byte, error) {
	// Lire la taille du message
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("failed to read size: %w", err)
	}

	// Vérifier la taille
	if size == 0 {
		return nil, ErrEmptyMessage
	}

	if size > MaxMsgSize*2 { // Marge pour les métadonnées JSON
		return nil, ErrMessageTooLarge
	}

	// Lire les données
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Désérialiser le message
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	// Déchiffrer le message
	plaintext, err := sc.DecryptMessage(&msg)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Close nettoie le canal sécurisé
func (sc *SecureChannel) Close() {
	// Effacer les clés de la mémoire
	secureZeroMemory(sc.encryptKey[:])
	secureZeroMemory(sc.decryptKey[:])
}

// GetOverhead retourne la taille de l'overhead par message
func (sc *SecureChannel) GetOverhead() int {
	// secretbox.Overhead + nonce + métadonnées JSON approximatives
	return secretbox.Overhead + NonceSize + 100
}

// ValidateMessage valide qu'un message est bien formé
func ValidateMessage(msg *Message) error {
	if msg == nil {
		return errors.New("nil message")
	}

	if msg.ID == "" {
		return errors.New("empty message ID")
	}

	if msg.Timestamp == 0 {
		return errors.New("invalid timestamp")
	}

	if len(msg.Data) == 0 {
		return errors.New("empty message data")
	}

	if len(msg.Nonce) != NonceSize {
		return errors.New("invalid nonce size")
	}

	return nil
}

// generateMessageID génère un ID unique pour un message
func generateMessageID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback en cas d'erreur
		return fmt.Sprintf("msg_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", bytes)
}
