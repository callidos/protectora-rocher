package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/callidos/protectora-rocher/pkg/utils"
)

// AudioProtocol représente le protocole de communication audio sécurisé
type AudioProtocol struct {
	conn        io.ReadWriter
	sessionKey  []byte
	aesGCM      cipher.AEAD
	isActive    bool
	mutex       sync.RWMutex
	stopChannel chan struct{}
}

// AudioMessage représente un message audio chiffré
type AudioMessage struct {
	Type      uint8 // 0: AUDIO_DATA, 1: CONTROL, 2: END_CALL
	Timestamp int64
	Nonce     []byte
	Data      []byte
}

const (
	AUDIO_DATA = 0
	CONTROL    = 1
	END_CALL   = 2

	MAX_AUDIO_SIZE = 1024 * 16 // 16KB max par message
	NONCE_SIZE     = 12
	KEY_SIZE       = 32
)

// CORRECTION MAJEURE: NewAudioProtocol prend maintenant une clé de session existante
// au lieu de générer sa propre clé indépendamment
func NewAudioProtocol(conn io.ReadWriter, sharedSessionKey []byte) (*AudioProtocol, error) {
	if conn == nil {
		return nil, errors.New("connexion nulle")
	}

	if len(sharedSessionKey) < 32 {
		return nil, errors.New("clé de session insuffisante (minimum 32 bytes)")
	}

	// CORRECTION: Utiliser la clé de session partagée au lieu d'en générer une nouvelle
	sessionKey := make([]byte, 32)
	copy(sessionKey, sharedSessionKey[:32])

	// Création du chiffrement AES-GCM
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("échec de création du cipher AES : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("échec de création de l'AES-GCM : %v", err)
	}

	protocol := &AudioProtocol{
		conn:        conn,
		sessionKey:  sessionKey,
		aesGCM:      aesGCM,
		isActive:    false,
		stopChannel: make(chan struct{}),
	}

	utils.Logger.Info("Protocole audio sécurisé initialisé avec clé partagée", map[string]interface{}{
		"key_size": len(sessionKey),
	})

	return protocol, nil
}

// CORRECTION: Fonction supprimée car remplacée par l'utilisation de clés partagées
// generateSessionKey() n'est plus nécessaire

// StartSecureCall démarre un appel audio sécurisé
func (ap *AudioProtocol) StartSecureCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if ap.isActive {
		return errors.New("appel déjà en cours")
	}

	ap.isActive = true
	ap.stopChannel = make(chan struct{})

	// Envoi du message de début d'appel
	if err := ap.sendControlMessage("START_CALL"); err != nil {
		ap.isActive = false
		return fmt.Errorf("échec d'envoi du message de début : %v", err)
	}

	utils.Logger.Info("Appel audio sécurisé démarré", map[string]interface{}{})
	return nil
}

// SendAudioData envoie des données audio chiffrées
func (ap *AudioProtocol) SendAudioData(audioData []byte) error {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return errors.New("aucun appel en cours")
	}

	if len(audioData) > MAX_AUDIO_SIZE {
		return errors.New("données audio trop volumineuses")
	}

	message := AudioMessage{
		Type:      AUDIO_DATA,
		Timestamp: time.Now().UnixNano(),
		Data:      audioData,
	}

	return ap.sendMessage(&message)
}

// ReceiveAudioData reçoit et déchiffre des données audio
func (ap *AudioProtocol) ReceiveAudioData() ([]byte, error) {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return nil, errors.New("aucun appel en cours")
	}

	message, err := ap.receiveMessage()
	if err != nil {
		return nil, err
	}

	if message.Type != AUDIO_DATA {
		return nil, fmt.Errorf("type de message inattendu : %d", message.Type)
	}

	return message.Data, nil
}

// StopSecureCall arrête l'appel audio sécurisé
func (ap *AudioProtocol) StopSecureCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if !ap.isActive {
		return errors.New("aucun appel en cours")
	}

	// Envoi du message de fin d'appel
	if err := ap.sendControlMessage("END_CALL"); err != nil {
		utils.Logger.Error("Échec d'envoi du message de fin", map[string]interface{}{
			"error": err,
		})
	}

	ap.isActive = false
	close(ap.stopChannel)

	utils.Logger.Info("Appel audio sécurisé terminé", map[string]interface{}{})
	return nil
}

// IsActive retourne l'état de l'appel
func (ap *AudioProtocol) IsActive() bool {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	return ap.isActive
}

// sendMessage envoie un message chiffré
func (ap *AudioProtocol) sendMessage(message *AudioMessage) error {
	// Génération d'un nonce unique
	nonce := make([]byte, ap.aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("échec de génération du nonce : %v", err)
	}

	// Chiffrement des données
	encrypted := ap.aesGCM.Seal(nil, nonce, message.Data, nil)

	// Préparation du message final
	message.Nonce = nonce
	message.Data = encrypted

	// Sérialisation du message
	serialized, err := ap.serializeMessage(message)
	if err != nil {
		return fmt.Errorf("échec de sérialisation : %v", err)
	}

	// Envoi du message
	if _, err := ap.conn.Write(serialized); err != nil {
		return fmt.Errorf("échec d'envoi : %v", err)
	}

	utils.Logger.Debug("Message audio chiffré envoyé", map[string]interface{}{
		"type": message.Type,
		"size": len(encrypted),
	})

	return nil
}

// receiveMessage reçoit et déchiffre un message
func (ap *AudioProtocol) receiveMessage() (*AudioMessage, error) {
	// Lecture de l'en-tête (taille du message)
	headerBuf := make([]byte, 4)
	if _, err := io.ReadFull(ap.conn, headerBuf); err != nil {
		return nil, fmt.Errorf("échec de lecture de l'en-tête : %v", err)
	}

	messageSize := binary.BigEndian.Uint32(headerBuf)
	if messageSize > MAX_AUDIO_SIZE+1024 { // Marge pour les métadonnées
		return nil, errors.New("message trop volumineux")
	}

	// Lecture du message complet
	messageBuf := make([]byte, messageSize)
	if _, err := io.ReadFull(ap.conn, messageBuf); err != nil {
		return nil, fmt.Errorf("échec de lecture du message : %v", err)
	}

	// Désérialisation
	message, err := ap.deserializeMessage(messageBuf)
	if err != nil {
		return nil, fmt.Errorf("échec de désérialisation : %v", err)
	}

	// Déchiffrement
	decrypted, err := ap.aesGCM.Open(nil, message.Nonce, message.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("échec de déchiffrement : %v", err)
	}

	message.Data = decrypted

	utils.Logger.Debug("Message audio déchiffré reçu", map[string]interface{}{
		"type": message.Type,
		"size": len(decrypted),
	})

	return message, nil
}

// sendControlMessage envoie un message de contrôle
func (ap *AudioProtocol) sendControlMessage(control string) error {
	message := AudioMessage{
		Type:      CONTROL,
		Timestamp: time.Now().UnixNano(),
		Data:      []byte(control),
	}

	return ap.sendMessage(&message)
}

// serializeMessage sérialise un message pour l'envoi
func (ap *AudioProtocol) serializeMessage(message *AudioMessage) ([]byte, error) {
	var buf []byte

	// Ajout du type
	buf = append(buf, message.Type)

	// Ajout du timestamp
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(message.Timestamp))
	buf = append(buf, timestampBytes...)

	// Ajout de la taille du nonce
	buf = append(buf, byte(len(message.Nonce)))

	// Ajout du nonce
	buf = append(buf, message.Nonce...)

	// Ajout des données
	buf = append(buf, message.Data...)

	// Préparation du message final avec en-tête de taille
	finalBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(finalBuf, uint32(len(buf)))
	finalBuf = append(finalBuf, buf...)

	return finalBuf, nil
}

// deserializeMessage désérialise un message reçu
func (ap *AudioProtocol) deserializeMessage(data []byte) (*AudioMessage, error) {
	if len(data) < 10 { // Type(1) + Timestamp(8) + NonceSize(1)
		return nil, errors.New("message trop court")
	}

	message := &AudioMessage{}
	offset := 0

	// Lecture du type
	message.Type = data[offset]
	offset++

	// Lecture du timestamp
	message.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Lecture de la taille du nonce
	nonceSize := int(data[offset])
	offset++

	if len(data) < offset+nonceSize {
		return nil, errors.New("nonce incomplet")
	}

	// Lecture du nonce
	message.Nonce = data[offset : offset+nonceSize]
	offset += nonceSize

	// Lecture des données
	message.Data = data[offset:]

	return message, nil
}

// GetSessionInfo retourne des informations sur la session (pour debugging)
func (ap *AudioProtocol) GetSessionInfo() map[string]interface{} {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	return map[string]interface{}{
		"is_active":        ap.isActive,
		"session_key_size": len(ap.sessionKey),
		"nonce_size":       ap.aesGCM.NonceSize(),
	}
}
