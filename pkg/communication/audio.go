package communication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/callidos/protectora-rocher/pkg/utils"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	AUDIO_DATA = 0
	CONTROL    = 1
	END_CALL   = 2

	maxAudioSize   = 32 * 1024 // 32KB max par message
	audioNonceSize = 24
	audioKeySize   = 32
)

var (
	ErrNoActiveCall   = errors.New("no active call")
	ErrCallInProgress = errors.New("call already in progress")
	ErrAudioTooLarge  = errors.New("audio data too large")
	ErrInvalidAudio   = errors.New("invalid audio message")
	ErrConnectionLost = errors.New("connection lost")
)

// AudioMessage représente un message audio
type AudioMessage struct {
	Type      uint8
	Timestamp int64
	Data      []byte
}

// AudioProtocol gère la communication audio sécurisée avec NaCl secretbox
type AudioProtocol struct {
	conn     io.ReadWriter
	key      [audioKeySize]byte
	isActive bool
	mutex    sync.RWMutex
	stopChan chan struct{}
}

// NewAudioProtocol crée un nouveau protocole audio avec la clé de session partagée
func NewAudioProtocol(conn io.ReadWriter, sessionKey []byte) (*AudioProtocol, error) {
	if conn == nil {
		return nil, errors.New("connection required")
	}
	if len(sessionKey) < 32 {
		return nil, errors.New("session key too short")
	}

	// Dérivation de clé spécifique pour l'audio
	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-audio-encryption-v2")
	h := hkdf.New(sha256.New, sessionKey, salt, info)

	var key [audioKeySize]byte
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return nil, fmt.Errorf("audio key derivation failed: %w", err)
	}

	ap := &AudioProtocol{
		conn:     conn,
		key:      key,
		isActive: false,
		stopChan: make(chan struct{}),
	}

	utils.Logger.Info("Protocole audio initialisé", map[string]interface{}{
		"cipher": "NaCl-secretbox",
	})

	return ap, nil
}

// StartCall démarre un appel audio sécurisé
func (ap *AudioProtocol) StartCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if ap.isActive {
		return ErrCallInProgress
	}

	ap.isActive = true
	ap.stopChan = make(chan struct{})

	// Envoi du signal de début d'appel
	if err := ap.sendControlMessage("START_CALL"); err != nil {
		ap.isActive = false
		return fmt.Errorf("failed to start call: %w", err)
	}

	utils.Logger.Info("Appel audio démarré", nil)
	return nil
}

// SendAudio envoie des données audio chiffrées
func (ap *AudioProtocol) SendAudio(audioData []byte) error {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return ErrNoActiveCall
	}

	if len(audioData) > maxAudioSize {
		return ErrAudioTooLarge
	}

	message := &AudioMessage{
		Type:      AUDIO_DATA,
		Timestamp: time.Now().UnixNano(),
		Data:      audioData,
	}

	return ap.sendMessage(message)
}

// ReceiveAudio reçoit et déchiffre des données audio
func (ap *AudioProtocol) ReceiveAudio() ([]byte, error) {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return nil, ErrNoActiveCall
	}

	message, err := ap.receiveMessage()
	if err != nil {
		return nil, err
	}

	if message.Type != AUDIO_DATA {
		return nil, fmt.Errorf("unexpected message type: %d", message.Type)
	}

	return message.Data, nil
}

// StopCall arrête l'appel audio
func (ap *AudioProtocol) StopCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if !ap.isActive {
		return ErrNoActiveCall
	}

	// Envoi du signal de fin d'appel
	if err := ap.sendControlMessage("END_CALL"); err != nil {
		utils.Logger.Error("Échec envoi fin d'appel", map[string]interface{}{
			"error": err.Error(),
		})
	}

	ap.isActive = false
	close(ap.stopChan)

	utils.Logger.Info("Appel audio terminé", nil)
	return nil
}

// IsActive retourne l'état de l'appel
func (ap *AudioProtocol) IsActive() bool {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	return ap.isActive
}

// sendMessage envoie un message audio chiffré avec NaCl secretbox
func (ap *AudioProtocol) sendMessage(message *AudioMessage) error {
	// Sérialisation du message
	serialized, err := ap.serializeMessage(message)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Génération du nonce
	var nonce [audioNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement avec NaCl secretbox
	encrypted := secretbox.Seal(nil, serialized, &nonce, &ap.key)

	// Format final: taille + nonce + données chiffrées
	finalData := make([]byte, 4+audioNonceSize+len(encrypted))
	binary.BigEndian.PutUint32(finalData[:4], uint32(audioNonceSize+len(encrypted)))
	copy(finalData[4:4+audioNonceSize], nonce[:])
	copy(finalData[4+audioNonceSize:], encrypted)

	// Envoi
	if _, err := ap.conn.Write(finalData); err != nil {
		return ErrConnectionLost
	}

	return nil
}

// receiveMessage reçoit et déchiffre un message audio
func (ap *AudioProtocol) receiveMessage() (*AudioMessage, error) {
	// Lecture de la taille du message
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(ap.conn, sizeBuf); err != nil {
		return nil, ErrConnectionLost
	}

	size := binary.BigEndian.Uint32(sizeBuf)
	if size > maxAudioSize*2 { // Marge pour les métadonnées
		return nil, ErrInvalidAudio
	}

	// Lecture du message complet
	messageBuf := make([]byte, size)
	if _, err := io.ReadFull(ap.conn, messageBuf); err != nil {
		return nil, ErrConnectionLost
	}

	// Extraction du nonce
	if len(messageBuf) < audioNonceSize {
		return nil, ErrInvalidAudio
	}

	var nonce [audioNonceSize]byte
	copy(nonce[:], messageBuf[:audioNonceSize])
	encrypted := messageBuf[audioNonceSize:]

	// Déchiffrement avec NaCl secretbox
	decrypted, ok := secretbox.Open(nil, encrypted, &nonce, &ap.key)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	// Désérialisation
	message, err := ap.deserializeMessage(decrypted)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return message, nil
}

// sendControlMessage envoie un message de contrôle
func (ap *AudioProtocol) sendControlMessage(control string) error {
	message := &AudioMessage{
		Type:      CONTROL,
		Timestamp: time.Now().UnixNano(),
		Data:      []byte(control),
	}
	return ap.sendMessage(message)
}

// serializeMessage sérialise un message
func (ap *AudioProtocol) serializeMessage(message *AudioMessage) ([]byte, error) {
	// Format simple: Type(1) + Timestamp(8) + DataLength(4) + Data
	buf := make([]byte, 1+8+4+len(message.Data))

	buf[0] = message.Type
	binary.BigEndian.PutUint64(buf[1:9], uint64(message.Timestamp))
	binary.BigEndian.PutUint32(buf[9:13], uint32(len(message.Data)))
	copy(buf[13:], message.Data)

	return buf, nil
}

// deserializeMessage désérialise un message
func (ap *AudioProtocol) deserializeMessage(data []byte) (*AudioMessage, error) {
	if len(data) < 13 { // Type(1) + Timestamp(8) + DataLength(4)
		return nil, ErrInvalidAudio
	}

	message := &AudioMessage{
		Type:      data[0],
		Timestamp: int64(binary.BigEndian.Uint64(data[1:9])),
	}

	dataLength := binary.BigEndian.Uint32(data[9:13])
	if len(data) < 13+int(dataLength) {
		return nil, ErrInvalidAudio
	}

	message.Data = data[13 : 13+dataLength]
	return message, nil
}

// GetStats retourne les statistiques de la session audio
func (ap *AudioProtocol) GetStats() map[string]interface{} {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	return map[string]interface{}{
		"is_active":  ap.isActive,
		"cipher":     "NaCl-secretbox",
		"nonce_size": audioNonceSize,
		"max_size":   maxAudioSize,
	}
}
