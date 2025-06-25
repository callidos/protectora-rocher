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

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	replayWindow      = 30 * time.Second
	messageSizeLimit  = 16 * 1024 * 1024
	maxSkippedMsgs    = 100
	maxHistoryEntries = 10000
	cleanupInterval   = 5 * time.Minute
	maxTTL            = 86400 // 24 hours maximum
	protocolVersion   = 2
	protocolNonceSize = 24
	protocolKeySize   = 32
	sequenceWindow    = 1000 // Sliding window for sequence numbers
)

// Unified error to avoid information oracles
var (
	ErrInvalidMessage = errors.New("invalid message")
)

// Global validator instance with custom validations
var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validations
	validate.RegisterValidation("safe_string", validateSafeString)
	validate.RegisterValidation("session_id", validateSessionID)
	validate.RegisterValidation("nonce_size", validateNonceSize)
}

// Custom validation functions
func validateSafeString(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	for _, r := range str {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func validateSessionID(fl validator.FieldLevel) bool {
	sessionID := fl.Field().String()

	// Permettre les SessionID vides pour la compatibilité
	if len(sessionID) == 0 {
		return true
	}

	if len(sessionID) > 64 {
		return false
	}

	// Check only safe characters
	for _, r := range sessionID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validateNonceSize(fl validator.FieldLevel) bool {
	nonce := fl.Field().Bytes()
	return len(nonce) == 0 || len(nonce) == 16 // Empty or 16 bytes
}

// messageEntry structure for storing message metadata
type messageEntry struct {
	timestamp time.Time
	seq       uint64
	hash      [16]byte // Partial hash for duplicate detection
}

// MessageHistory manages anti-replay with automatic cleanup and strict sequence validation
type MessageHistory struct {
	messages            map[uint64]messageEntry
	hashIndex           map[[16]byte]uint64 // Hash index for fast duplicate detection
	mu                  sync.RWMutex
	lastCleanup         time.Time
	cleanupStop         chan struct{}
	expectedSeqMin      uint64 // Minimum expected sequence for sliding window
	expectedSeqMax      uint64 // Maximum expected sequence for sliding window
	sequenceInitialized bool   // Flag to know if sequence has been initialized
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

	// Start automatic cleanup
	go mh.periodicCleanup()

	return mh
}

// periodicCleanup periodically cleans old entries
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

// cleanup removes expired entries efficiently
func (mh *MessageHistory) cleanup() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-replayWindow)

	// Clean old messages and adjust sequence window
	oldestValidSeq := uint64(^uint64(0)) // Max uint64
	toDelete := make([]uint64, 0, len(mh.messages)/10)

	for seq, entry := range mh.messages {
		if entry.timestamp.Before(cutoff) {
			toDelete = append(toDelete, seq)
		} else if seq < oldestValidSeq {
			oldestValidSeq = seq
		}
	}

	// Remove expired entries
	for _, seq := range toDelete {
		if entry, exists := mh.messages[seq]; exists {
			delete(mh.hashIndex, entry.hash)
			delete(mh.messages, seq)
		}
	}

	// Adjust sequence window if messages were deleted
	if len(toDelete) > 0 && oldestValidSeq != uint64(^uint64(0)) {
		mh.expectedSeqMin = oldestValidSeq
	}

	mh.lastCleanup = now
}

// generateMessageHash generates a partial hash for a message
func generateMessageHash(seq uint64, timestamp int64, data []byte) [16]byte {
	var hash [16]byte

	// Combine seq, timestamp and data sample
	binary.BigEndian.PutUint64(hash[0:8], seq)
	binary.BigEndian.PutUint64(hash[8:16], uint64(timestamp))

	// XOR with data sample for more uniqueness
	if len(data) > 0 {
		for i := 0; i < 16 && i < len(data); i++ {
			hash[i] ^= data[i]
		}
	}

	return hash
}

// CheckAndStore checks and stores a message with optimized DoS protection and strict sequence validation
func (mh *MessageHistory) CheckAndStore(seq uint64, timestamp int64, data []byte) error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Conditional cleanup for performance
	now := time.Now()
	if now.Sub(mh.lastCleanup) > cleanupInterval {
		mh.cleanupUnsafe(now)
	}

	// Check size limit to avoid memory exhaustion
	if len(mh.messages) >= maxHistoryEntries {
		return ErrInvalidMessage
	}

	// Validate sequence window with replay attack protection
	if !mh.isSequenceValid(seq) {
		return ErrInvalidMessage
	}

	// Generate message hash
	hash := generateMessageHash(seq, timestamp, data)

	// Fast hash check
	if _, exists := mh.hashIndex[hash]; exists {
		return ErrInvalidMessage
	}

	// Sequence check
	if _, exists := mh.messages[seq]; exists {
		return ErrInvalidMessage
	}

	// Store message
	entry := messageEntry{
		timestamp: now,
		seq:       seq,
		hash:      hash,
	}

	mh.messages[seq] = entry
	mh.hashIndex[hash] = seq

	// Update sequence window
	mh.updateSequenceWindow(seq)

	return nil
}

// isSequenceValid checks if a sequence number is in the valid window
func (mh *MessageHistory) isSequenceValid(seq uint64) bool {
	if !mh.sequenceInitialized {
		// First message - initialize window
		mh.expectedSeqMin = seq
		mh.expectedSeqMax = seq + sequenceWindow
		mh.sequenceInitialized = true
		return true
	}

	// Check that sequence is in sliding window
	if seq < mh.expectedSeqMin {
		// Message too old - possible replay
		return false
	}

	if seq > mh.expectedSeqMax {
		// Message too recent - possible attack
		// Allow limited offset for delayed messages
		if seq > mh.expectedSeqMax+sequenceWindow {
			return false
		}
	}

	return true
}

// updateSequenceWindow updates the sliding sequence window
func (mh *MessageHistory) updateSequenceWindow(seq uint64) {
	if seq > mh.expectedSeqMax {
		// Advance window
		advance := seq - mh.expectedSeqMax
		mh.expectedSeqMin += advance
		mh.expectedSeqMax = seq + sequenceWindow
	}
}

// cleanupUnsafe non-thread-safe version for internal use
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

// Reset cleans history safely
func (mh *MessageHistory) Reset() {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Clean maps
	for seq := range mh.messages {
		delete(mh.messages, seq)
	}
	for hash := range mh.hashIndex {
		delete(mh.hashIndex, hash)
	}

	// Reset sequence window
	mh.expectedSeqMin = 0
	mh.expectedSeqMax = 0
	mh.sequenceInitialized = false
	mh.lastCleanup = time.Now()
}

// Stop stops automatic cleanup
func (mh *MessageHistory) Stop() {
	close(mh.cleanupStop)
}

// GetStats returns optimized statistics
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

// Session history isolation - no more global singleton
var (
	sessionHistories   = make(map[string]*MessageHistory)
	sessionHistoriesMu sync.RWMutex
)

// getSessionHistory returns history for a given session
func getSessionHistory(sessionID string) *MessageHistory {
	sessionHistoriesMu.RLock()
	history, exists := sessionHistories[sessionID]
	sessionHistoriesMu.RUnlock()

	if exists {
		return history
	}

	// Create new history for this session
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Double check after acquiring write lock
	if history, exists := sessionHistories[sessionID]; exists {
		return history
	}

	history = NewMessageHistory()
	sessionHistories[sessionID] = history
	return history
}

// Envelope message structure with enhanced security and validation
type Envelope struct {
	Seq       uint64 `json:"seq" validate:"required,min=0"`
	Timestamp int64  `json:"ts" validate:"required"`
	TTL       int    `json:"ttl,omitempty" validate:"min=0,max=86400"`
	Data      string `json:"data" validate:"required,max=1048576,safe_string"`
	Version   int    `json:"v" validate:"eq=2"`
	Nonce     []byte `json:"nonce,omitempty" validate:"nonce_size"`
	SessionID string `json:"sid,omitempty" validate:"session_id"`
}

// ValidateEnvelope validates an envelope using validator tags
func ValidateEnvelope(env *Envelope) error {
	return validate.Struct(env)
}

// generateSecureNonce generates a secure nonce
func generateSecureNonce() []byte {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic("failed to generate secure nonce: " + err.Error())
	}
	return nonce
}

// SendMessage sends encrypted message with NaCl secretbox
func SendMessage(w io.Writer, message string, key []byte, seq uint64, ttl int) error {
	return SendMessageWithSession(w, message, key, seq, ttl, "")
}

// SendMessageWithSession sends encrypted message with session isolation
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
		ttl = 0 // Unlimited TTL or default value
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

	// Validate envelope with tags
	if err := ValidateEnvelope(&envelope); err != nil {
		return fmt.Errorf("envelope validation failed: %w", err)
	}

	// Serialize envelope
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Check size before encryption
	if len(envJSON) > messageSizeLimit/2 {
		return ErrInvalidMessage
	}

	// Derive key for protocol
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	defer secureZeroResistant(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	// Generate nonce for NaCl
	var nonce [protocolNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt with NaCl secretbox
	encrypted := secretbox.Seal(nil, envJSON, &nonce, &secretKey)

	// Final format: nonce + ciphertext + newline
	finalMessage := make([]byte, protocolNonceSize+len(encrypted)+1)
	copy(finalMessage[:protocolNonceSize], nonce[:])
	copy(finalMessage[protocolNonceSize:protocolNonceSize+len(encrypted)], encrypted)
	finalMessage[len(finalMessage)-1] = '\n'

	// Final size check
	if len(finalMessage) > messageSizeLimit {
		return ErrInvalidMessage
	}

	// Atomic message send
	_, err = w.Write(finalMessage)

	// Secure cleanup resistant to optimizations
	secureZeroResistant(secretKey[:])
	secureZeroResistant(nonce[:])
	secureZeroResistant(finalMessage)

	return err
}

// ReceiveMessage receives and decrypts message with NaCl secretbox
func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	return ReceiveMessageWithSession(r, key, "")
}

// ReceiveMessageWithSession receives and decrypts message with session isolation
func ReceiveMessageWithSession(r io.Reader, key []byte, sessionID string) (string, error) {
	if r == nil {
		return "", errors.New("reader cannot be nil")
	}
	if len(key) == 0 {
		return "", errors.New("empty key")
	}

	// Read with strict size limit
	reader := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", ErrInvalidMessage // Unified error
	}

	// Remove newline character
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	if line == "" {
		return "", ErrInvalidMessage
	}

	// Convert to bytes
	data := []byte(line)
	defer secureZeroResistant(data)

	// Validate minimum size
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return "", ErrInvalidMessage
	}

	// Derive key for protocol
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return "", ErrInvalidMessage // Error normalization
	}
	defer secureZeroResistant(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	// Extract components
	var nonce [protocolNonceSize]byte
	copy(nonce[:], data[:protocolNonceSize])
	ciphertext := data[protocolNonceSize:]

	// Decrypt with NaCl secretbox
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return "", ErrInvalidMessage // Error normalization
	}
	defer secureZeroResistant(decrypted)

	// Deserialize envelope
	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", ErrInvalidMessage
	}

	// Validate envelope with tags
	if err := ValidateEnvelope(&envelope); err != nil {
		return "", ErrInvalidMessage
	}

	// Unified message validation with session
	if err := validateMessageWithSession(envelope, sessionID); err != nil {
		return "", ErrInvalidMessage // Always same error
	}

	// Secure cleanup
	secureZeroResistant(secretKey[:])
	secureZeroResistant(nonce[:])

	return envelope.Data, nil
}

// validateMessageWithSession validates a message with oracle protection and session isolation
func validateMessageWithSession(env Envelope, expectedSessionID string) error {
	now := time.Now().Unix()

	// Session isolation check
	if expectedSessionID != "" && env.SessionID != expectedSessionID {
		return ErrInvalidMessage
	}

	// Time window verification
	windowSeconds := int64(replayWindow.Seconds())
	timeDiff := now - env.Timestamp

	// Temporal validation with unified tolerance
	if timeDiff > windowSeconds || timeDiff < -5 {
		return ErrInvalidMessage
	}

	// Expiration check (TTL)
	if env.TTL > 0 && now > env.Timestamp+int64(env.TTL) {
		return ErrInvalidMessage
	}

	// Anti-replay verification with DoS protection and session isolation
	sessionKey := env.SessionID
	if sessionKey == "" {
		sessionKey = "default" // Default session for backward compatibility
	}

	history := getSessionHistory(sessionKey)
	if err := history.CheckAndStore(env.Seq, env.Timestamp, []byte(env.Data)); err != nil {
		return ErrInvalidMessage // Unified error
	}

	return nil
}

// SendMessageWithRetry sends message with intelligent retry
func SendMessageWithRetry(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int) error {
	return SendMessageWithRetryAndSession(w, message, key, seq, ttl, maxRetries, "")
}

// SendMessageWithRetryAndSession sends message with intelligent retry and session isolation
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
				// Exponential backoff with jitter
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

// ReceiveMessageWithTimeout receives message with configurable timeout
func ReceiveMessageWithTimeout(r io.Reader, key []byte, timeout time.Duration) (string, error) {
	return ReceiveMessageWithTimeoutAndSession(r, key, timeout, "")
}

// ReceiveMessageWithTimeoutAndSession receives message with configurable timeout and session isolation
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

// ResetMessageHistory safely resets global history
func ResetMessageHistory() {
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	// Stop and clean all session histories
	for sessionID, history := range sessionHistories {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// ResetSessionHistory resets history for a specific session
func ResetSessionHistory(sessionID string) {
	sessionHistoriesMu.Lock()
	defer sessionHistoriesMu.Unlock()

	if history, exists := sessionHistories[sessionID]; exists {
		history.Stop()
		history.Reset()
		delete(sessionHistories, sessionID)
	}
}

// StopMessageHistory stops automatic cleanup for all sessions
func StopMessageHistory() {
	sessionHistoriesMu.RLock()
	histories := make([]*MessageHistory, 0, len(sessionHistories))
	for _, history := range sessionHistories {
		histories = append(histories, history)
	}
	sessionHistoriesMu.RUnlock()

	// Stop all histories
	for _, history := range histories {
		history.Stop()
	}
}

// GetMessageHistoryStats returns global history statistics
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

// GetSessionHistoryStats returns statistics for a specific session
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

// ValidateMessageIntegrity validates message integrity without decryption
func ValidateMessageIntegrity(encryptedMessage string) error {
	if encryptedMessage == "" {
		return ErrInvalidMessage
	}

	data := []byte(encryptedMessage)
	// Basic size validation
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return ErrInvalidMessage
	}

	return nil
}

// EstimateMessageOverhead estimates message overhead
func EstimateMessageOverhead(messageSize int) int {
	// Estimation: JSON envelope + NaCl encryption + newline
	jsonOverhead := 150                                          // Approximate JSON metadata (including SessionID)
	encryptionOverhead := protocolNonceSize + secretbox.Overhead // Nonce + NaCl overhead
	newlineOverhead := 1

	return jsonOverhead + encryptionOverhead + newlineOverhead
}

// Additional helper functions for validation

// ValidateUsername validates username with tags
func ValidateUsername(username string) error {
	type UsernameStruct struct {
		Username string `validate:"required,min=3,max=64,alphanum"`
	}

	return validate.Struct(&UsernameStruct{Username: username})
}

// ValidateSessionIDString validates a session ID string
func ValidateSessionIDString(sessionID string) error {
	type SessionStruct struct {
		SessionID string `validate:"session_id"`
	}

	return validate.Struct(&SessionStruct{SessionID: sessionID})
}

// ValidateMessageData validates message data content
func ValidateMessageData(data string) error {
	type DataStruct struct {
		Data string `validate:"required,max=1048576,safe_string"`
	}

	return validate.Struct(&DataStruct{Data: data})
}

// RegisterCustomValidation allows registering additional custom validations
func RegisterCustomValidation(tag string, fn validator.Func) error {
	return validate.RegisterValidation(tag, fn)
}

// GetValidatorInstance returns the global validator instance for advanced usage
func GetValidatorInstance() *validator.Validate {
	return validate
}
