package communication

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"sync"
	"time"
)

const (
	replayWindow      = 30 * time.Second
	messageSizeLimit  = 16 * 1024 * 1024
	maxSkippedMsgs    = 100
	maxHistoryEntries = 10000
	cleanupInterval   = 5 * time.Minute
	maxTTL            = 86400 // 24 heures maximum
	protocolVersion   = 2
)

// Erreur unifiée pour éviter les oracles d'information
var (
	ErrInvalidMessage = errors.New("invalid message")
)

// messageEntry structure pour stocker les métadonnées des messages
type messageEntry struct {
	timestamp time.Time
	seq       uint64
	hash      [16]byte // Hash partiel pour détecter les duplicatas
}

// MessageHistory gère l'anti-rejeu avec nettoyage automatique et optimisations
type MessageHistory struct {
	messages    map[uint64]messageEntry
	hashIndex   map[[16]byte]uint64 // Index par hash pour détection rapide
	mu          sync.RWMutex
	lastCleanup time.Time
	cleanupStop chan struct{}
}

func NewMessageHistory() *MessageHistory {
	mh := &MessageHistory{
		messages:    make(map[uint64]messageEntry),
		hashIndex:   make(map[[16]byte]uint64),
		lastCleanup: time.Now(),
		cleanupStop: make(chan struct{}),
	}

	// Démarrer le nettoyage automatique
	go mh.periodicCleanup()

	return mh
}

// periodicCleanup nettoie périodiquement les anciennes entrées
func (mh *MessageHistory) periodicCleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mh.cleanup()
		case <-mh.cleanupStop:
			return
		}
	}
}

// cleanup supprime les entrées expirées de manière efficace
func (mh *MessageHistory) cleanup() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-replayWindow)

	// Collecter les entrées à supprimer
	toDelete := make([]uint64, 0, len(mh.messages)/10)
	for seq, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, seq)
		}
	}

	// Supprimer les entrées expirées
	for _, seq := range toDelete {
		if entry, exists := mh.messages[seq]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, seq)
		}
	}

	mh.lastCleanup = now
}

// generateMessageHash génère un hash partiel pour un message
func generateMessageHash(seq uint64, timestamp int64, data []byte) [16]byte {
	var hash [16]byte

	// Combiner seq, timestamp et un échantillon des données
	binary.BigEndian.PutUint64(hash[0:8], seq)
	binary.BigEndian.PutUint64(hash[8:16], uint64(timestamp))

	// XOR avec un échantillon des données pour plus d'unicité
	if len(data) > 0 {
		for i := 0; i < 16 && i < len(data); i++ {
			hash[i] ^= data[i]
		}
	}

	return hash
}

// CheckAndStore vérifie et stocke un message avec protection DoS optimisée
func (mh *MessageHistory) CheckAndStore(seq uint64, timestamp int64, data []byte) error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Nettoyage conditionnel pour performance
	now := time.Now()
	if now.Sub(mh.lastCleanup) > cleanupInterval {
		mh.cleanupUnsafe(now)
	}

	// Vérifier la limite de taille pour éviter l'épuisement mémoire
	if len(mh.messages) >= maxHistoryEntries {
		return ErrInvalidMessage
	}

	// Générer le hash du message
	hash := generateMessageHash(seq, timestamp, data)

	// Vérification rapide par hash
	if _, exists := mh.hashIndex[hash]; exists {
		return ErrInvalidMessage
	}

	// Vérification par séquence
	if _, exists := mh.messages[seq]; exists {
		return ErrInvalidMessage
	}

	// Stocker le message
	entry := messageEntry{
		timestamp: now,
		seq:       seq,
		hash:      hash,
	}

	mh.messages[seq] = entry
	mh.hashIndex[hash] = seq

	return nil
}

// cleanupUnsafe version non thread-safe pour usage interne
func (mh *MessageHistory) cleanupUnsafe(now time.Time) {
	cutoff := now.Add(-replayWindow)

	toDelete := make([]uint64, 0, len(mh.messages)/10)
	for seq, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, seq)
		}
	}

	for _, seq := range toDelete {
		if entry, exists := mh.messages[seq]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, seq)
		}
	}

	mh.lastCleanup = now
}

// Reset nettoie l'historique de manière sécurisée
func (mh *MessageHistory) Reset() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Nettoyer les maps
	for seq := range mh.messages {
		delete(mh.messages, seq)
	}
	for hash := range mh.hashIndex {
		delete(mh.hashIndex, hash)
	}

	mh.lastCleanup = time.Now()
}

// Stop arrête le nettoyage automatique
func (mh *MessageHistory) Stop() {
	close(mh.cleanupStop)
}

// GetStats retourne les statistiques optimisées
func (mh *MessageHistory) GetStats() map[string]interface{} {
	mh.mu.RLock()
	defer mh.mu.RUnlock()

	return map[string]interface{}{
		"total_messages": len(mh.messages),
		"hash_entries":   len(mh.hashIndex),
		"last_cleanup":   mh.lastCleanup,
		"max_entries":    maxHistoryEntries,
	}
}

var (
	globalHistory     *MessageHistory
	globalHistoryOnce sync.Once
)

func getGlobalHistory() *MessageHistory {
	globalHistoryOnce.Do(func() {
		globalHistory = NewMessageHistory()
	})
	return globalHistory
}

// Envelope structure du message avec sécurité renforcée
type Envelope struct {
	Seq       uint64 `json:"seq"`
	Timestamp int64  `json:"ts"`
	TTL       int    `json:"ttl,omitempty"`
	Data      string `json:"data"`
	Version   int    `json:"v"`
	Nonce     []byte `json:"nonce,omitempty"` // Nonce additionnel pour plus de sécurité
}

// generateSecureNonce génère un nonce sécurisé
func generateSecureNonce() []byte {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("failed to generate secure nonce: " + err.Error())
	}
	return nonce
}

// SendMessage envoie un message chiffré avec protection renforcée
func SendMessage(w io.Writer, message string, key []byte, seq uint64, ttl int) error {
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	if len(message) == 0 {
		return errors.New("empty message")
	}
	if len(key) == 0 {
		return errors.New("empty key")
	}
	if ttl < 0 || ttl > maxTTL {
		ttl = 0 // TTL illimité ou valeur par défaut
	}

	envelope := Envelope{
		Seq:       seq,
		Timestamp: time.Now().Unix(),
		TTL:       ttl,
		Data:      message,
		Version:   protocolVersion,
		Nonce:     generateSecureNonce(),
	}

	// Sérialisation de l'enveloppe
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Vérification de la taille avant chiffrement
	if len(envJSON) > messageSizeLimit/2 {
		return ErrInvalidMessage
	}

	// Chiffrement avec authentification intégrée
	encrypted, err := EncryptAESGCM(envJSON, key)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Vérification finale de la taille
	finalMessage := append([]byte(encrypted), '\n')
	if len(finalMessage) > messageSizeLimit {
		return ErrInvalidMessage
	}

	// Envoi atomique du message
	_, err = w.Write(finalMessage)
	return err
}

// ReceiveMessage reçoit et déchiffre un message avec validation unifiée
func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	if r == nil {
		return "", errors.New("reader cannot be nil")
	}
	if len(key) == 0 {
		return "", errors.New("empty key")
	}

	// Lecture avec limite de taille stricte
	reader := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", ErrInvalidMessage // Erreur unifiée
	}

	// Suppression du caractère de fin de ligne
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	if line == "" {
		return "", ErrInvalidMessage
	}

	// Déchiffrement avec gestion d'erreur unifiée
	decrypted, err := DecryptAESGCM(line, key)
	if err != nil {
		return "", ErrInvalidMessage // Normalisation des erreurs
	}

	// Désérialisation de l'enveloppe
	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", ErrInvalidMessage
	}

	// Validation unifiée du message
	if err := validateMessage(envelope); err != nil {
		return "", ErrInvalidMessage // Toujours la même erreur
	}

	return envelope.Data, nil
}

// validateMessage valide un message avec protection contre les oracles
func validateMessage(env Envelope) error {
	now := time.Now().Unix()

	// Validation des champs obligatoires
	if env.Data == "" || env.Version != protocolVersion {
		return ErrInvalidMessage
	}

	// Vérification de la fenêtre temporelle
	windowSeconds := int64(replayWindow.Seconds())
	timeDiff := now - env.Timestamp

	// Validation temporelle avec tolérance unifiée
	if timeDiff > windowSeconds || timeDiff < -5 {
		return ErrInvalidMessage
	}

	// Vérification de l'expiration (TTL)
	if env.TTL > 0 && now > env.Timestamp+int64(env.TTL) {
		return ErrInvalidMessage
	}

	// Validation de la cohérence du TTL
	if env.TTL < 0 || env.TTL > maxTTL {
		return ErrInvalidMessage
	}

	// Validation du nonce si présent
	if len(env.Nonce) > 0 && len(env.Nonce) != 16 {
		return ErrInvalidMessage
	}

	// Vérification anti-rejeu avec protection DoS
	history := getGlobalHistory()
	if err := history.CheckAndStore(env.Seq, env.Timestamp, []byte(env.Data)); err != nil {
		return ErrInvalidMessage // Erreur unifiée
	}

	return nil
}

// SendMessageWithRetry envoie un message avec retry intelligent
func SendMessageWithRetry(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int) error {
	if maxRetries < 0 {
		maxRetries = 3
	}

	var lastErr error
	backoff := 100 * time.Millisecond

	for i := 0; i <= maxRetries; i++ {
		if err := SendMessage(w, message, key, seq, ttl); err != nil {
			lastErr = err
			if i < maxRetries {
				// Backoff exponentiel avec jitter
				jitter := time.Duration(mathrand.Int63n(int64(backoff / 2)))
				time.Sleep(backoff + jitter)
				backoff *= 2
				continue
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// ReceiveMessageWithTimeout reçoit un message avec timeout configurable
func ReceiveMessageWithTimeout(r io.Reader, key []byte, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	type result struct {
		message string
		err     error
	}

	resultChan := make(chan result, 1)

	go func() {
		defer close(resultChan)
		msg, err := ReceiveMessage(r, key)
		resultChan <- result{message: msg, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.message, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("receive timeout after %v", timeout)
	}
}

// ResetMessageHistory réinitialise l'historique global de manière sécurisée
func ResetMessageHistory() {
	history := getGlobalHistory()
	history.Reset()
}

// StopMessageHistory arrête le nettoyage automatique
func StopMessageHistory() {
	if globalHistory != nil {
		globalHistory.Stop()
	}
}

// GetMessageHistoryStats retourne les statistiques de l'historique global
func GetMessageHistoryStats() map[string]interface{} {
	history := getGlobalHistory()
	return history.GetStats()
}

// ValidateMessageIntegrity valide l'intégrité d'un message sans le déchiffrer
func ValidateMessageIntegrity(encryptedMessage string) error {
	return ValidateEncryptedData(encryptedMessage)
}

// EstimateMessageOverhead estime l'overhead d'un message
func EstimateMessageOverhead(messageSize int) int {
	// Estimation: JSON envelope + chiffrement + base64
	jsonOverhead := 100           // Métadonnées JSON approximatives
	encryptionOverhead := 32 + 16 // Nonce + tag GCM
	base64Overhead := (messageSize + jsonOverhead + encryptionOverhead) / 3

	return jsonOverhead + encryptionOverhead + base64Overhead
}
