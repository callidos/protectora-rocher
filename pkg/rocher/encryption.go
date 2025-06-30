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
	ID           string `json:"id"`
	Timestamp    int64  `json:"timestamp"`
	Type         string `json:"type"` // NOUVEAU CHAMP AJOUTÉ
	Recipient    string `json:"recipient"`
	SessionToken string `json:"session_token"`
	Data         []byte `json:"data"`  // Données chiffrées
	Nonce        []byte `json:"nonce"` // Nonce pour le chiffrement
}

// SecureChannel gère le chiffrement/déchiffrement des messages
type SecureChannel struct {
	sendKey    [KeySize]byte // Clé pour envoyer des messages
	receiveKey [KeySize]byte // Clé pour recevoir des messages
}

// NewSecureChannel crée un nouveau canal sécurisé à partir d'un secret partagé
func NewSecureChannel(sharedSecret []byte, isInitiator bool) (*SecureChannel, error) {
	if len(sharedSecret) < KeySize {
		return nil, errors.New("shared secret too short")
	}

	sc := &SecureChannel{}

	// Dérivation des clés de chiffrement et déchiffrement
	if err := sc.deriveKeys(sharedSecret, isInitiator); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return sc, nil
}

// deriveKeys dérive les clés de chiffrement/déchiffrement avec HKDF
// Les clés sont inversées entre initiateur et répondeur pour permettre la communication
func (sc *SecureChannel) deriveKeys(secret []byte, isInitiator bool) error {
	salt := []byte("rocher-simple-salt-v1")

	// Définir les contextes pour les clés directionnelles
	var sendInfo, receiveInfo []byte
	if isInitiator {
		sendInfo = []byte("rocher-initiator-to-responder-v1")
		receiveInfo = []byte("rocher-responder-to-initiator-v1")
	} else {
		sendInfo = []byte("rocher-responder-to-initiator-v1")
		receiveInfo = []byte("rocher-initiator-to-responder-v1")
	}

	// Clé pour envoyer des messages
	hkdfSend := hkdf.New(sha256.New, secret, salt, sendInfo)
	if _, err := io.ReadFull(hkdfSend, sc.sendKey[:]); err != nil {
		return fmt.Errorf("failed to derive send key: %w", err)
	}

	// Clé pour recevoir des messages
	hkdfReceive := hkdf.New(sha256.New, secret, salt, receiveInfo)
	if _, err := io.ReadFull(hkdfReceive, sc.receiveKey[:]); err != nil {
		return fmt.Errorf("failed to derive receive key: %w", err)
	}

	// Vérifier que les clés ne sont pas nulles
	if isAllZeros(sc.sendKey[:]) || isAllZeros(sc.receiveKey[:]) {
		return errors.New("derived keys are zero")
	}

	// Vérifier que les clés sont différentes (sécurité supplémentaire)
	if ConstantTimeCompare(sc.sendKey[:], sc.receiveKey[:]) {
		return errors.New("send and receive keys are identical")
	}

	return nil
}

// EncryptMessage chiffre un message avec NaCl secretbox
func (sc *SecureChannel) EncryptMessage(plaintext []byte, messageType, recipient, sessionToken string) (*Message, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyMessage
	}

	if len(plaintext) > MaxMsgSize {
		return nil, ErrMessageTooLarge
	}

	// Validation côté envoi
	if messageType == "" {
		return nil, errors.New("empty message type")
	}

	if recipient == "" {
		return nil, errors.New("empty recipient")
	}

	if sessionToken == "" {
		return nil, errors.New("empty session token")
	}

	// Génération d'un nonce aléatoire
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement avec NaCl secretbox en utilisant la clé d'envoi
	encrypted := secretbox.Seal(nil, plaintext, &nonce, &sc.sendKey)

	message := &Message{
		ID:           generateMessageID(),
		Timestamp:    time.Now().Unix(),
		Type:         messageType, // NOUVEAU CHAMP UTILISÉ
		Recipient:    recipient,
		SessionToken: sessionToken,
		Data:         encrypted,
		Nonce:        nonce[:],
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

	// Déchiffrement avec NaCl secretbox en utilisant la clé de réception
	plaintext, ok := secretbox.Open(nil, msg.Data, &nonce, &sc.receiveKey)
	if !ok {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// SendMessage sérialise et envoie un message chiffré
func (sc *SecureChannel) SendMessage(plaintext []byte, messageType, recipient, sessionToken string, writer io.Writer) error {
	// Chiffrer le message
	msg, err := sc.EncryptMessage(plaintext, messageType, recipient, sessionToken)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Sérialiser en JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Vérifier la taille finale
	if len(data) > MaxMsgSize*2 {
		return fmt.Errorf("serialized message too large: %d bytes", len(data))
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
func (sc *SecureChannel) ReceiveMessage(reader io.Reader) ([]byte, string, string, string, error) {
	// Lire la taille du message
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, "", "", "", fmt.Errorf("failed to read size: %w", err)
	}

	// Vérifier la taille
	if size == 0 {
		return nil, "", "", "", ErrEmptyMessage
	}

	if size > MaxMsgSize*2 { // Marge pour les métadonnées JSON
		return nil, "", "", "", fmt.Errorf("message too large: %d bytes", size)
	}

	// Lire les données
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, "", "", "", fmt.Errorf("failed to read data: %w", err)
	}

	// Désérialiser le message
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, "", "", "", fmt.Errorf("deserialization failed: %w", err)
	}

	// Valider le message avant déchiffrement
	if err := ValidateMessage(&msg); err != nil {
		return nil, "", "", "", fmt.Errorf("invalid message: %w", err)
	}

	// Déchiffrer le message
	plaintext, err := sc.DecryptMessage(&msg)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, msg.Type, msg.Recipient, msg.SessionToken, nil // RETOURNE AUSSI LE TYPE
}

// Close nettoie le canal sécurisé
func (sc *SecureChannel) Close() {
	// Effacer les clés de la mémoire de manière sécurisée
	secureZeroMemory(sc.sendKey[:])
	secureZeroMemory(sc.receiveKey[:])
}

// GetOverhead retourne la taille de l'overhead par message
func (sc *SecureChannel) GetOverhead() int {
	// secretbox.Overhead + nonce + métadonnées JSON approximatives
	return secretbox.Overhead + NonceSize + 200 // Augmenté pour le champ type et session_token
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

	// Validation du type de message - OBLIGATOIRE ET NON-VIDE
	if msg.Type == "" {
		return errors.New("empty message type")
	}

	// Validation du destinataire
	if msg.Recipient == "" {
		return errors.New("empty recipient")
	}

	// Validation du session token - OBLIGATOIRE ET NON-VIDE
	if msg.SessionToken == "" {
		return errors.New("empty session token")
	}

	// Vérifier que le timestamp n'est pas trop ancien ou futur
	now := time.Now().Unix()
	if msg.Timestamp < now-3600 || msg.Timestamp > now+300 { // 1h passé, 5min futur
		return fmt.Errorf("timestamp out of range: %d (now: %d)", msg.Timestamp, now)
	}

	if len(msg.Data) == 0 {
		return errors.New("empty message data")
	}

	if len(msg.Data) < secretbox.Overhead {
		return errors.New("message data too short for secretbox")
	}

	if len(msg.Nonce) != NonceSize {
		return fmt.Errorf("invalid nonce size: got %d, expected %d", len(msg.Nonce), NonceSize)
	}

	// Vérifier que le nonce n'est pas entièrement à zéro
	if isAllZeros(msg.Nonce) {
		return errors.New("nonce is all zeros")
	}

	return nil
}

// generateMessageID génère un ID unique pour un message
func generateMessageID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback en cas d'erreur avec timestamp seul
		return fmt.Sprintf("msg_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", bytes)
}
