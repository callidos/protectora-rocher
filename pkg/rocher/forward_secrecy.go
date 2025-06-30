// forward_secrecy.go
package rocher

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// KeyRotationConfig configure la rotation des clés
type KeyRotationConfig struct {
	// Rotation basée sur le temps
	TimeInterval time.Duration // Ex: toutes les 30 minutes

	// Rotation basée sur l'usage
	MaxMessages uint64 // Ex: après 1000 messages
	MaxBytes    uint64 // Ex: après 10MB

	// Rotation forcée
	ForceRotation bool

	// Activation
	Enabled bool
}

// DefaultKeyRotationConfig retourne une config par défaut
func DefaultKeyRotationConfig() *KeyRotationConfig {
	return &KeyRotationConfig{
		TimeInterval:  30 * time.Minute,
		MaxMessages:   1000,
		MaxBytes:      10 * 1024 * 1024, // 10MB
		ForceRotation: false,
		Enabled:       true,
	}
}

// KeyRotationState suit l'état de rotation des clés
type KeyRotationState struct {
	// Compteurs
	messageCount uint64
	byteCount    uint64
	lastRotation time.Time
	rotationID   uint64

	// Synchronisation
	mu                 sync.RWMutex
	rotationInProgress bool
}

// SecureChannelWithFS combine SecureChannel avec forward secrecy
type SecureChannelWithFS struct {
	// Canal de base
	currentChannel *SecureChannel

	// Configuration de rotation
	rotationConfig *KeyRotationConfig
	rotationState  *KeyRotationState

	// Clés précédentes pour déchiffrer d'anciens messages
	previousChannels map[uint64]*SecureChannel
	maxOldChannels   int

	// Secret maître pour dériver de nouvelles clés
	masterSecret []byte
	isInitiator  bool

	// NOUVEAU: Synchronisation entre pairs
	peerRotationID uint64 // ID de rotation du pair distant
	rotationSync   sync.RWMutex

	// Callbacks
	onKeyRotation func(rotationID uint64) error

	mu sync.RWMutex
}

// MessageWithFS étend Message avec les métadonnées FS
type MessageWithFS struct {
	ID           string `json:"id"`
	Timestamp    int64  `json:"timestamp"`
	Recipient    string `json:"recipient"`
	SessionToken string `json:"session_token"` // NOUVEAU CHAMP AJOUTÉ
	Data         []byte `json:"data"`
	Nonce        []byte `json:"nonce"`

	// Métadonnées Forward Secrecy
	RotationID     uint64 `json:"rotation_id"`      // ID de rotation de l'expéditeur
	PeerRotationID uint64 `json:"peer_rotation_id"` // ID de rotation du destinataire (NOUVEAU)
	FSVersion      int    `json:"fs_version"`       // Version du protocole FS
}

// NewSecureChannelWithFS crée un canal avec forward secrecy
func NewSecureChannelWithFS(sharedSecret []byte, isInitiator bool) (*SecureChannelWithFS, error) {
	// Créer le canal de base
	baseChannel, err := NewSecureChannel(sharedSecret, isInitiator)
	if err != nil {
		return nil, err
	}

	// Créer le canal avec FS
	sc := &SecureChannelWithFS{
		currentChannel: baseChannel,
		rotationConfig: DefaultKeyRotationConfig(),
		rotationState: &KeyRotationState{
			lastRotation: time.Now(),
			rotationID:   0,
		},
		previousChannels: make(map[uint64]*SecureChannel),
		maxOldChannels:   5, // Garder 5 générations de clés
		masterSecret:     copyBytes(sharedSecret),
		isInitiator:      isInitiator,
		peerRotationID:   0, // NOUVEAU: ID du pair initialisé à 0
	}

	return sc, nil
}

// SetKeyRotationConfig configure la rotation
func (sc *SecureChannelWithFS) SetKeyRotationConfig(config *KeyRotationConfig) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.rotationConfig = config
}

// SetOnKeyRotation définit le callback de rotation
func (sc *SecureChannelWithFS) SetOnKeyRotation(callback func(uint64) error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.onKeyRotation = callback
}

// NeedsRotation vérifie si une rotation est nécessaire
func (sc *SecureChannelWithFS) NeedsRotation() bool {
	if !sc.rotationConfig.Enabled {
		return false
	}

	sc.rotationState.mu.RLock()
	defer sc.rotationState.mu.RUnlock()

	// Vérifier le temps
	if time.Since(sc.rotationState.lastRotation) >= sc.rotationConfig.TimeInterval {
		return true
	}

	// Vérifier le nombre de messages
	if sc.rotationState.messageCount >= sc.rotationConfig.MaxMessages {
		return true
	}

	// Vérifier le volume de données
	if sc.rotationState.byteCount >= sc.rotationConfig.MaxBytes {
		return true
	}

	// Rotation forcée
	if sc.rotationConfig.ForceRotation {
		return true
	}

	return false
}

// RotateKeys effectue la rotation des clés
func (sc *SecureChannelWithFS) RotateKeys() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.rotationState.mu.Lock()
	defer sc.rotationState.mu.Unlock()

	if sc.rotationState.rotationInProgress {
		return errors.New("rotation already in progress")
	}

	sc.rotationState.rotationInProgress = true
	defer func() {
		sc.rotationState.rotationInProgress = false
	}()

	// Sauvegarder le canal actuel
	currentRotationID := sc.rotationState.rotationID
	sc.previousChannels[currentRotationID] = sc.currentChannel

	// Nettoyer les anciens canaux si nécessaire
	sc.cleanupOldChannels()

	// Générer de nouvelles clés
	newRotationID := currentRotationID + 1
	newSecret, err := sc.deriveNewSecret(newRotationID)
	if err != nil {
		return fmt.Errorf("failed to derive new secret: %w", err)
	}

	// Créer le nouveau canal
	newChannel, err := NewSecureChannel(newSecret, sc.isInitiator)
	if err != nil {
		secureZeroMemory(newSecret)
		return fmt.Errorf("failed to create new channel: %w", err)
	}

	// Nettoyer le secret temporaire
	secureZeroMemory(newSecret)

	// Remplacer le canal actuel
	sc.currentChannel = newChannel

	// Mettre à jour l'état
	sc.rotationState.rotationID = newRotationID
	sc.rotationState.lastRotation = time.Now()
	sc.rotationState.messageCount = 0
	sc.rotationState.byteCount = 0
	sc.rotationConfig.ForceRotation = false

	// Appeler le callback si défini
	if sc.onKeyRotation != nil {
		if err := sc.onKeyRotation(newRotationID); err != nil {
			return fmt.Errorf("rotation callback failed: %w", err)
		}
	}

	return nil
}

// NOUVEAU: UpdatePeerRotationID met à jour l'ID de rotation du pair
func (sc *SecureChannelWithFS) UpdatePeerRotationID(peerRotationID uint64) {
	sc.rotationSync.Lock()
	defer sc.rotationSync.Unlock()

	if peerRotationID > sc.peerRotationID {
		sc.peerRotationID = peerRotationID
	}
}

// NOUVEAU: GetPeerRotationID retourne l'ID de rotation du pair
func (sc *SecureChannelWithFS) GetPeerRotationID() uint64 {
	sc.rotationSync.RLock()
	defer sc.rotationSync.RUnlock()
	return sc.peerRotationID
}

// deriveNewSecret dérive un nouveau secret à partir du secret maître
func (sc *SecureChannelWithFS) deriveNewSecret(rotationID uint64) ([]byte, error) {
	// Utiliser HKDF avec un contexte unique pour chaque rotation
	salt := []byte("rocher-key-rotation-v1")
	info := fmt.Sprintf("rotation-%d-%s", rotationID, time.Now().Format("2006-01-02"))

	hkdf := hkdf.New(sha256.New, sc.masterSecret, salt, []byte(info))

	newSecret := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf, newSecret); err != nil {
		return nil, err
	}

	// Vérifier que le nouveau secret n'est pas zéro
	if isAllZeros(newSecret) {
		return nil, errors.New("derived secret is zero")
	}

	return newSecret, nil
}

// cleanupOldChannels supprime les canaux trop anciens
func (sc *SecureChannelWithFS) cleanupOldChannels() {
	if len(sc.previousChannels) <= sc.maxOldChannels {
		return
	}

	// Trouver les canaux les plus anciens à supprimer
	oldestID := sc.rotationState.rotationID - uint64(sc.maxOldChannels)

	for id, channel := range sc.previousChannels {
		if id <= oldestID {
			channel.Close()
			delete(sc.previousChannels, id)
		}
	}
}

// EncryptMessage avec rotation automatique
func (sc *SecureChannelWithFS) EncryptMessage(plaintext []byte, recipient, sessionToken string) (*MessageWithFS, error) {
	// Validation côté envoi
	if recipient == "" {
		return nil, errors.New("empty recipient")
	}

	if sessionToken == "" {
		return nil, errors.New("empty session token")
	}

	// Vérifier si rotation nécessaire
	if sc.NeedsRotation() {
		if err := sc.RotateKeys(); err != nil {
			return nil, fmt.Errorf("key rotation failed: %w", err)
		}
	}

	// Chiffrer avec les clés actuelles
	baseMsg, err := sc.currentChannel.EncryptMessage(plaintext, recipient, sessionToken)
	if err != nil {
		return nil, err
	}

	// Créer le message avec métadonnées FS
	sc.rotationState.mu.Lock()
	rotationID := sc.rotationState.rotationID
	sc.rotationState.messageCount++
	sc.rotationState.byteCount += uint64(len(plaintext))
	sc.rotationState.mu.Unlock()

	// NOUVEAU: Inclure l'ID de rotation du pair
	peerRotationID := sc.GetPeerRotationID()

	msg := &MessageWithFS{
		ID:             baseMsg.ID,
		Timestamp:      baseMsg.Timestamp,
		Recipient:      baseMsg.Recipient,
		SessionToken:   baseMsg.SessionToken, // NOUVEAU CHAMP INCLUS
		Data:           baseMsg.Data,
		Nonce:          baseMsg.Nonce,
		RotationID:     rotationID,
		PeerRotationID: peerRotationID, // NOUVEAU
		FSVersion:      1,
	}

	return msg, nil
}

// DecryptMessage avec support des anciennes clés
func (sc *SecureChannelWithFS) DecryptMessage(msg *MessageWithFS) ([]byte, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	// NOUVEAU: Mettre à jour l'ID de rotation du pair
	sc.UpdatePeerRotationID(msg.RotationID)

	// Créer un Message de base pour la compatibilité
	baseMsg := &Message{
		ID:           msg.ID,
		Timestamp:    msg.Timestamp,
		Recipient:    msg.Recipient,
		SessionToken: msg.SessionToken, // NOUVEAU CHAMP INCLUS
		Data:         msg.Data,
		Nonce:        msg.Nonce,
	}

	// Essayer avec le canal actuel d'abord
	sc.rotationState.mu.RLock()
	currentRotationID := sc.rotationState.rotationID
	sc.rotationState.mu.RUnlock()

	if msg.RotationID == currentRotationID {
		return sc.currentChannel.DecryptMessage(baseMsg)
	}

	// Essayer avec les anciens canaux
	if oldChannel, exists := sc.previousChannels[msg.RotationID]; exists {
		return oldChannel.DecryptMessage(baseMsg)
	}

	return nil, fmt.Errorf("no keys available for rotation ID %d", msg.RotationID)
}

// SendMessage sérialise et envoie un message chiffré avec FS
func (sc *SecureChannelWithFS) SendMessage(plaintext []byte, recipient, sessionToken string, writer io.Writer) error {
	// Chiffrer le message
	msg, err := sc.EncryptMessage(plaintext, recipient, sessionToken)
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

	// Envoyer la taille puis les données (même format que SecureChannel)
	size := uint32(len(data))
	if err := binary.Write(writer, binary.BigEndian, size); err != nil {
		return fmt.Errorf("failed to write size: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// ReceiveMessage reçoit et déchiffre un message avec support FS
func (sc *SecureChannelWithFS) ReceiveMessage(reader io.Reader) ([]byte, string, string, error) {
	// Lire la taille du message (même format que SecureChannel)
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, "", "", fmt.Errorf("failed to read size: %w", err)
	}

	// Vérifier la taille
	if size == 0 {
		return nil, "", "", ErrEmptyMessage
	}

	if size > MaxMsgSize*2 {
		return nil, "", "", fmt.Errorf("message too large: %d bytes", size)
	}

	// Lire les données
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, "", "", fmt.Errorf("failed to read data: %w", err)
	}

	// Désérialiser le message
	var msg MessageWithFS
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, "", "", fmt.Errorf("deserialization failed: %w", err)
	}

	// Valider le message avant déchiffrement
	if err := sc.ValidateMessageWithFS(&msg); err != nil {
		return nil, "", "", fmt.Errorf("invalid message: %w", err)
	}

	// Déchiffrer le message
	plaintext, err := sc.DecryptMessage(&msg)
	if err != nil {
		return nil, "", "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, msg.Recipient, msg.SessionToken, nil // RETOURNE AUSSI LE SESSION TOKEN
}

// ValidateMessageWithFS valide un message avec métadonnées FS
func (sc *SecureChannelWithFS) ValidateMessageWithFS(msg *MessageWithFS) error {
	if msg == nil {
		return errors.New("nil message")
	}

	if msg.ID == "" {
		return errors.New("empty message ID")
	}

	if msg.Timestamp == 0 {
		return errors.New("invalid timestamp")
	}

	if msg.Recipient == "" {
		return errors.New("empty recipient")
	}

	// VALIDATION : Session token obligatoire et non-vide
	if msg.SessionToken == "" {
		return errors.New("empty session token")
	}

	// Vérifier que le timestamp n'est pas trop ancien ou futur
	now := time.Now().Unix()
	if msg.Timestamp < now-3600 || msg.Timestamp > now+300 {
		return fmt.Errorf("timestamp out of range: %d (now: %d)", msg.Timestamp, now)
	}

	if len(msg.Data) == 0 {
		return errors.New("empty message data")
	}

	if len(msg.Nonce) != NonceSize {
		return fmt.Errorf("invalid nonce size: got %d, expected %d", len(msg.Nonce), NonceSize)
	}

	// Vérifier que le nonce n'est pas entièrement à zéro
	if isAllZeros(msg.Nonce) {
		return errors.New("nonce is all zeros")
	}

	// Validations spécifiques à FS
	if msg.FSVersion != 1 {
		return fmt.Errorf("unsupported FS version: %d", msg.FSVersion)
	}

	// MODIFIÉ: Validation plus permissive pour les IDs de rotation
	sc.rotationState.mu.RLock()
	currentRotationID := sc.rotationState.rotationID
	sc.rotationState.mu.RUnlock()

	// Permettre les messages avec des IDs futurs (synchronisation)
	maxFutureRotationID := currentRotationID + 2 // Tolérance de 2 rotations futures
	if msg.RotationID > maxFutureRotationID {
		return fmt.Errorf("rotation ID too far in future: %d > %d", msg.RotationID, maxFutureRotationID)
	}

	maxOldRotationID := uint64(0)
	if currentRotationID > uint64(sc.maxOldChannels) {
		maxOldRotationID = currentRotationID - uint64(sc.maxOldChannels)
	}

	if msg.RotationID < maxOldRotationID {
		return fmt.Errorf("rotation ID too old: %d < %d", msg.RotationID, maxOldRotationID)
	}

	return nil
}

// Close nettoie toutes les clés
func (sc *SecureChannelWithFS) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Fermer le canal principal
	if sc.currentChannel != nil {
		sc.currentChannel.Close()
	}

	// Fermer tous les anciens canaux
	for _, channel := range sc.previousChannels {
		channel.Close()
	}

	// Nettoyer le secret maître
	secureZeroMemory(sc.masterSecret)

	// Vider les maps
	sc.previousChannels = make(map[uint64]*SecureChannel)
}

// GetOverhead retourne la taille de l'overhead par message
func (sc *SecureChannelWithFS) GetOverhead() int {
	// Overhead de base + métadonnées FS
	baseOverhead := sc.currentChannel.GetOverhead()
	return baseOverhead + 120 // JSON overhead pour rotation_id, peer_rotation_id, fs_version et session_token
}

// GetRotationStats retourne les statistiques de rotation
func (sc *SecureChannelWithFS) GetRotationStats() map[string]interface{} {
	sc.rotationState.mu.RLock()
	defer sc.rotationState.mu.RUnlock()

	peerRotationID := sc.GetPeerRotationID()

	return map[string]interface{}{
		"current_rotation_id":     sc.rotationState.rotationID,
		"peer_rotation_id":        peerRotationID, // NOUVEAU
		"last_rotation":           sc.rotationState.lastRotation,
		"messages_since_rotation": sc.rotationState.messageCount,
		"bytes_since_rotation":    sc.rotationState.byteCount,
		"old_channels_count":      len(sc.previousChannels),
		"rotation_enabled":        sc.rotationConfig.Enabled,
		"needs_rotation":          sc.NeedsRotation(),
		"rotation_in_progress":    sc.rotationState.rotationInProgress,
		"next_rotation_time":      sc.rotationState.lastRotation.Add(sc.rotationConfig.TimeInterval),
		"max_old_channels":        sc.maxOldChannels,
		"time_until_rotation":     sc.rotationConfig.TimeInterval - time.Since(sc.rotationState.lastRotation),
		"messages_until_rotation": sc.rotationConfig.MaxMessages - sc.rotationState.messageCount,
		"bytes_until_rotation":    sc.rotationConfig.MaxBytes - sc.rotationState.byteCount,
		"synchronized":            peerRotationID == sc.rotationState.rotationID, // NOUVEAU
	}
}

// ForceRotation force une rotation des clés au prochain message
func (sc *SecureChannelWithFS) ForceRotation() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.rotationConfig.ForceRotation = true
}

// GetCurrentRotationID retourne l'ID de rotation actuel
func (sc *SecureChannelWithFS) GetCurrentRotationID() uint64 {
	sc.rotationState.mu.RLock()
	defer sc.rotationState.mu.RUnlock()
	return sc.rotationState.rotationID
}

// SetMaxOldChannels configure le nombre max d'anciens canaux à garder
func (sc *SecureChannelWithFS) SetMaxOldChannels(max int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.maxOldChannels = max

	// Nettoyer immédiatement si nécessaire
	sc.cleanupOldChannels()
}
