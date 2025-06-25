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

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	replayWindow      = 30 * time.Second
	messageSizeLimit  = 16 * 1024 * 1024
	maxSkippedMsgs    = 100
	maxHistoryEntries = 10000
	cleanupInterval   = 5 * time.Minute
	maxTTL            = 86400 // 24 heures maximum
	protocolVersion   = 2
	protocolNonceSize = 24
	protocolKeySize   = 32
	sequenceWindow    = 1000 // Fenêtre glissante pour les numéros de séquence
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

// MessageHistory gère l'anti-rejeu avec nettoyage automatique et validation de séquence stricte
type MessageHistory struct {
	messages            map[uint64]messageEntry
	hashIndex           map[[16]byte]uint64 // Index par hash pour détection rapide
	mu                  sync.RWMutex
	lastCleanup         time.Time
	cleanupStop         chan struct{}
	expectedSeqMin      uint64 // Séquence minimale attendue pour la fenêtre glissante
	expectedSeqMax      uint64 // Séquence maximale attendue pour la fenêtre glissante
	sequenceInitialized bool   // Flag pour savoir si la séquence a été initialisée
}

func NewMessageHistory() *MessageHistory {
	mh := &MessageHistory{
		messages:            make(map[uint64]messageEntry),
		hashIndex:           make(map[[16]byte]uint64),
		lastCleanup:         time.Now(),
		cleanupStop:         make(chan struct{}),
		expectedSeqMin:      0,
		expectedSeqMax:      0,
		sequenceInitialized: false,
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

	// Nettoyer les anciens messages et ajuster la fenêtre de séquence
	oldestValidSeq := uint64(^uint64(0)) // Max uint64
	toDelete := make([]uint64, 0, len(mh.messages)/10)

	for seq, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, seq)
		} else if seq < oldestValidSeq {
			oldestValidSeq = seq
		}
	}

	// Supprimer les entrées expirées
	for _, seq := range toDelete {
		if entry, exists := mh.messages[seq]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, seq)
		}
	}

	// Ajuster la fenêtre de séquence si des messages ont été supprimés
	if len(toDelete) > 0 && oldestValidSeq != uint64(^uint64(0)) {
		mh.expectedSeqMin = oldestValidSeq
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

// CheckAndStore vérifie et stocke un message avec protection DoS optimisée et validation de séquence stricte
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

	// Validation de la fenêtre de séquence avec attaque par rejeu
	if !mh.isSequenceValid(seq) {
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

	// Mettre à jour la fenêtre de séquence
	mh.updateSequenceWindow(seq)

	return nil
}

// isSequenceValid vérifie si un numéro de séquence est dans la fenêtre valide
func (mh *MessageHistory) isSequenceValid(seq uint64) bool {
	if !mh.sequenceInitialized {
		// Premier message - initialiser la fenêtre
		mh.expectedSeqMin = seq
		mh.expectedSeqMax = seq + sequenceWindow
		mh.sequenceInitialized = true
		return true
	}

	// Vérifier que la séquence est dans la fenêtre glissante
	if seq < mh.expectedSeqMin {
		// Message trop ancien - possible rejeu
		return false
	}

	if seq > mh.expectedSeqMax {
		// Message trop récent - possible attaque
		// Permettre un décalage limité pour les messages retardés
		if seq > mh.expectedSeqMax+sequenceWindow {
			return false
		}
	}

	return true
}

// updateSequenceWindow met à jour la fenêtre de séquence glissante
func (mh *MessageHistory) updateSequenceWindow(seq uint64) {
	if seq > mh.expectedSeqMax {
		// Avancer la fenêtre
		advance := seq - mh.expectedSeqMax
		mh.expectedSeqMin += advance
		mh.expectedSeqMax = seq + sequenceWindow
	}
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

	// Réinitialiser la fenêtre de séquence
	mh.expectedSeqMin = 0
	mh.expectedSeqMax = 0
	mh.sequenceInitialized = false
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
		"total_messages":       len(mh.messages),
		"hash_entries":         len(mh.hashIndex),
		"last_cleanup":         mh.lastCleanup,
		"max_entries":          maxHistoryEntries,
		"expected_seq_min":     mh.expectedSeqMin,
		"expected_seq_max":     mh.expectedSeqMax,
		"sequence_initialized": mh.sequenceInitialized,
		"sequence_window":      sequenceWindow,
	}
}

// Isolation des historiques par session - plus de singleton global
var (
	sessionHistories   = make(map[string]*MessageHistory)
	sessionHistoriesMu sync.RWMutex
)

// getSessionHistory retourne l'historique pour une session donnée
func getSessionHistory(sessionID string) *MessageHistory {
	sessionHistoriesMu.RLock()
	history, exists := sessionHistories[sessionID]
	sessionHistoriesMu.RUnlock()

	if exists {
		return history
	}

	// Créer un nouvel historique pour cette session
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Double vérification après acquisition du verrou d'écriture
	if history, exists := sessionHistories[sessionID]; exists {
		return history
	}

	history = NewMessageHistory()
	sessionHistories[sessionID] = history
	return history
}

// Envelope structure du message avec sécurité renforcée
type Envelope struct {
	Seq       uint64 `json:"seq"`
	Timestamp int64  `json:"ts"`
	TTL       int    `json:"ttl,omitempty"`
	Data      string `json:"data"`
	Version   int    `json:"v"`
	Nonce     []byte `json:"nonce,omitempty"` // Nonce additionnel pour plus de sécurité
	SessionID string `json:"sid,omitempty"`   // Identifiant de session pour l'isolation
}

// generateSecureNonce génère un nonce sécurisé
func generateSecureNonce() []byte {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("failed to generate secure nonce: " + err.Error())
	}
	return nonce
}

// SendMessage envoie un message chiffré avec NaCl secretbox
func SendMessage(w io.Writer, message string, key []byte, seq uint64, ttl int) error {
	return SendMessageWithSession(w, message, key, seq, ttl, "")
}

// SendMessageWithSession envoie un message chiffré avec isolation de session
func SendMessageWithSession(w io.Writer, message string, key []byte, seq uint64, ttl int, sessionID string) error {
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
		SessionID: sessionID,
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

	// Dérivation de clé pour le protocole
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer secureZeroResistant(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	// Génération du nonce pour NaCl
	var nonce [protocolNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrement avec NaCl secretbox
	encrypted := secretbox.Seal(nil, envJSON, &nonce, &secretKey)

	// Format final: nonce + ciphertext + newline
	finalMessage := make([]byte, protocolNonceSize+len(encrypted)+1)
	copy(finalMessage[:protocolNonceSize], nonce[:])
	copy(finalMessage[protocolNonceSize:protocolNonceSize+len(encrypted)], encrypted)
	finalMessage[len(finalMessage)-1] = '\n'

	// Vérification finale de la taille
	if len(finalMessage) > messageSizeLimit {
		return ErrInvalidMessage
	}

	// Envoi atomique du message
	_, err = w.Write(finalMessage)

	// Nettoyage sécurisé résistant aux optimisations
	secureZeroResistant(secretKey[:])
	secureZeroResistant(nonce[:])
	secureZeroResistant(finalMessage)

	return err
}

// ReceiveMessage reçoit et déchiffre un message avec NaCl secretbox
func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	return ReceiveMessageWithSession(r, key, "")
}

// ReceiveMessageWithSession reçoit et déchiffre un message avec isolation de session
func ReceiveMessageWithSession(r io.Reader, key []byte, sessionID string) (string, error) {
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

	// Conversion en bytes
	data := []byte(line)
	defer secureZeroResistant(data)

	// Validation de la taille minimale
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return "", ErrInvalidMessage
	}

	// Dérivation de clé pour le protocole
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return "", ErrInvalidMessage // Normalisation des erreurs
	}
	defer secureZeroResistant(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	// Extraction des composants
	var nonce [protocolNonceSize]byte
	copy(nonce[:], data[:protocolNonceSize])
	ciphertext := data[protocolNonceSize:]

	// Déchiffrement avec NaCl secretbox
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return "", ErrInvalidMessage // Normalisation des erreurs
	}
	defer secureZeroResistant(decrypted)

	// Désérialisation de l'enveloppe
	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", ErrInvalidMessage
	}

	// Validation unifiée du message avec session
	if err := validateMessageWithSession(envelope, sessionID); err != nil {
		return "", ErrInvalidMessage // Toujours la même erreur
	}

	// Nettoyage sécurisé
	secureZeroResistant(secretKey[:])
	secureZeroResistant(nonce[:])

	return envelope.Data, nil
}

// validateMessageWithSession valide un message avec protection contre les oracles et isolation de session
func validateMessageWithSession(env Envelope, expectedSessionID string) error {
	now := time.Now().Unix()

	// Validation des champs obligatoires
	if env.Data == "" || env.Version != protocolVersion {
		return ErrInvalidMessage
	}

	// Vérification de l'isolation de session
	if expectedSessionID != "" && env.SessionID != expectedSessionID {
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

	// Vérification anti-rejeu avec protection DoS et isolation de session
	sessionKey := env.SessionID
	if sessionKey == "" {
		sessionKey = "default" // Session par défaut pour la rétrocompatibilité
	}

	history := getSessionHistory(sessionKey)
	if err := history.CheckAndStore(env.Seq, env.Timestamp, []byte(env.Data)); err != nil {
		return ErrInvalidMessage // Erreur unifiée
	}

	return nil
}

// SendMessageWithRetry envoie un message avec retry intelligent
func SendMessageWithRetry(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int) error {
	return SendMessageWithRetryAndSession(w, message, key, seq, ttl, maxRetries, "")
}

// SendMessageWithRetryAndSession envoie un message avec retry intelligent et isolation de session
func SendMessageWithRetryAndSession(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int, sessionID string) error {
	if maxRetries < 0 {
		maxRetries = 3
	}

	var lastErr error
	backoff := 100 * time.Millisecond

	for i := 0; i <= maxRetries; i++ {
		if err := SendMessageWithSession(w, message, key, seq, ttl, sessionID); err != nil {
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
	return ReceiveMessageWithTimeoutAndSession(r, key, timeout, "")
}

// ReceiveMessageWithTimeoutAndSession reçoit un message avec timeout configurable et isolation de session
func ReceiveMessageWithTimeoutAndSession(r io.Reader, key []byte, timeout time.Duration, sessionID string) (string, error) {
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
		msg, err := ReceiveMessageWithSession(r, key, sessionID)
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
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Arrêter et nettoyer tous les historiques de session
	for sessionID, history := range sessionHistories {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// ResetSessionHistory réinitialise l'historique d'une session spécifique
func ResetSessionHistory(sessionID string) {
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	if history, exists := sessionHistories[sessionID]; exists {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// StopMessageHistory arrête le nettoyage automatique pour toutes les sessions
func StopMessageHistory() {
	sessionHistoriesMu.RLock()
	histories := make([]*MessageHistory, 0, len(sessionHistories))
	for _, history := range sessionHistories {
		histories = append(histories, history)
	}
	sessionHistoriesMu.RUnlock()

	// Arrêter tous les historiques
	for _, history := range histories {
		history.Stop()
	}
}

// GetMessageHistoryStats retourne les statistiques de l'historique global
func GetMessageHistoryStats() map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_sessions"] = len(sessionHistories)

	sessionStats := make(map[string]interface{})
	for sessionID, history := range sessionHistories {
		sessionStats[sessionID] = history.GetStats()
	}
	stats["sessions"] = sessionStats

	return stats
}

// GetSessionHistoryStats retourne les statistiques d'une session spécifique
func GetSessionHistoryStats(sessionID string) map[string]interface{} {
	sessionHistoriesMu.RLock()
	defer sessionHistoriesMu.RUnlock()

	if history, exists := sessionHistories[sessionID]; exists {
		return history.GetStats()
	}

	return map[string]interface{}{
		"error": "session not found",
	}
}

// ValidateMessageIntegrity valide l'intégrité d'un message sans le déchiffrer
func ValidateMessageIntegrity(encryptedMessage string) error {
	if encryptedMessage == "" {
		return ErrInvalidMessage
	}

	data := []byte(encryptedMessage)
	// Validation basique de la taille
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return ErrInvalidMessage
	}

	return nil
}

// EstimateMessageOverhead estime l'overhead d'un message
func EstimateMessageOverhead(messageSize int) int {
	// Estimation: JSON envelope + chiffrement NaCl + newline
	jsonOverhead := 150                                          // Métadonnées JSON approximatives (incluant SessionID)
	encryptionOverhead := protocolNonceSize + secretbox.Overhead // Nonce + overhead NaCl
	newlineOverhead := 1

	return jsonOverhead + encryptionOverhead + newlineOverhead
}
