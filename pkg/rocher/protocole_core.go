package rocher

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	replayWindow      = 30 * time.Second
	messageSizeLimit  = 16 * 1024 * 1024
	maxSkippedMsgs    = 100
	maxHistoryEntries = 10000
	cleanupInterval   = 5 * time.Minute
	maxTTL            = 86400 // 24 hours maximum
	protocolVersion   = 3     // Version bumped for UUID support
	protocolNonceSize = 24
	protocolKeySize   = 32
	maxRecipientLen   = 64 // Maximum recipient identifier length
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
	validate.RegisterValidation("uuid_string", validateUUIDString)
	validate.RegisterValidation("recipient", validateRecipient)
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

func validateUUIDString(fl validator.FieldLevel) bool {
	uuidStr := fl.Field().String()
	if uuidStr == "" {
		return false
	}
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

func validateRecipient(fl validator.FieldLevel) bool {
	recipient := fl.Field().String()

	// Allow empty recipient for broadcast messages
	if len(recipient) == 0 {
		return true
	}

	if len(recipient) > maxRecipientLen {
		return false
	}

	// Check only safe characters for recipient
	for _, r := range recipient {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '@' || r == '.') {
			return false
		}
	}
	return true
}

// Envelope message structure with enhanced security, validation, recipient and UUID
type Envelope struct {
	ID        string `json:"id" validate:"required,uuid_string"` // UUID instead of sequence
	Timestamp int64  `json:"ts" validate:"required"`
	TTL       int    `json:"ttl,omitempty" validate:"min=0,max=86400"`
	Data      string `json:"data" validate:"required,max=1048576,safe_string"`
	Version   int    `json:"v" validate:"eq=3"` // Version 3 for UUID support
	Nonce     []byte `json:"nonce,omitempty" validate:"nonce_size"`
	SessionID string `json:"sid,omitempty" validate:"session_id"`
	Recipient string `json:"recipient,omitempty" validate:"recipient"` // New recipient field
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

// SendMessage sends encrypted message with NaCl secretbox (legacy interface)
func SendMessage(w io.Writer, message string, key []byte, seq uint64, ttl int) error {
	// Generate UUID for legacy interface
	msgID := uuid.New().String()
	return SendMessageWithRecipient(w, message, key, msgID, ttl, "", "")
}

// SendMessageWithSession sends encrypted message with session isolation (legacy interface)
func SendMessageWithSession(w io.Writer, message string, key []byte, seq uint64, ttl int, sessionID string) error {
	// Generate UUID for legacy interface
	msgID := uuid.New().String()
	return SendMessageWithRecipient(w, message, key, msgID, ttl, sessionID, "")
}

// SendMessageWithRecipient sends encrypted message with recipient and UUID
func SendMessageWithRecipient(w io.Writer, message string, key []byte, msgID string, ttl int, sessionID string, recipient string) error {
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

	// If no msgID provided, generate one
	if msgID == "" {
		msgID = uuid.New().String()
	}

	// Validate UUID format
	if _, err := uuid.Parse(msgID); err != nil {
		return fmt.Errorf("invalid message ID format: %w", err)
	}

	envelope := Envelope{
		ID:        msgID,
		Timestamp: time.Now().Unix(),
		TTL:       ttl,
		Data:      message,
		Version:   protocolVersion,
		Nonce:     generateSecureNonce(),
		SessionID: sessionID,
		Recipient: recipient,
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

// ReceiveMessage receives and decrypts message with NaCl secretbox (legacy interface)
func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	msg, _, _, err := ReceiveMessageWithDetails(r, key, "")
	return msg, err
}

// ReceiveMessageWithSession receives and decrypts message with session isolation (legacy interface)
func ReceiveMessageWithSession(r io.Reader, key []byte, sessionID string) (string, error) {
	msg, _, _, err := ReceiveMessageWithDetails(r, key, sessionID)
	return msg, err
}

// ReceiveMessageWithDetails receives and decrypts message with full details including recipient and UUID
func ReceiveMessageWithDetails(r io.Reader, key []byte, sessionID string) (message string, msgID string, recipient string, err error) {
	if r == nil {
		return "", "", "", errors.New("reader cannot be nil")
	}
	if len(key) == 0 {
		return "", "", "", errors.New("empty key")
	}

	// Read with strict size limit
	reader := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", "", ErrInvalidMessage // Unified error
	}

	// Remove newline character
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	if line == "" {
		return "", "", "", ErrInvalidMessage
	}

	// Convert to bytes
	data := []byte(line)
	defer secureZeroResistant(data)

	// Validate minimum size
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return "", "", "", ErrInvalidMessage
	}

	// Derive key for protocol
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return "", "", "", ErrInvalidMessage // Error normalization
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
		return "", "", "", ErrInvalidMessage // Error normalization
	}
	defer secureZeroResistant(decrypted)

	// Deserialize envelope
	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Validate envelope with tags
	if err := ValidateEnvelope(&envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Unified message validation with session and UUID
	if err := validateMessageWithDetailsAndSession(envelope, sessionID); err != nil {
		return "", "", "", ErrInvalidMessage // Always same error
	}

	// Secure cleanup
	secureZeroResistant(secretKey[:])
	secureZeroResistant(nonce[:])

	return envelope.Data, envelope.ID, envelope.Recipient, nil
}

// validateMessageWithDetailsAndSession validates a message with oracle protection, session isolation and UUID validation
func validateMessageWithDetailsAndSession(env Envelope, expectedSessionID string) error {
	now := time.Now().Unix()

	// Session isolation check
	if expectedSessionID != "" && env.SessionID != expectedSessionID {
		return ErrInvalidMessage
	}

	// UUID validation
	if _, err := uuid.Parse(env.ID); err != nil {
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
	if err := history.CheckAndStore(env.ID, env.Timestamp, env.Recipient, []byte(env.Data)); err != nil {
		return ErrInvalidMessage // Unified error
	}

	return nil
}

// SendMessageWithRetry sends message with intelligent retry (legacy interface)
func SendMessageWithRetry(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int) error {
	msgID := uuid.New().String()
	return SendMessageWithRetryAndRecipient(w, message, key, msgID, ttl, maxRetries, "", "")
}

// SendMessageWithRetryAndSession sends message with intelligent retry and session isolation (legacy interface)
func SendMessageWithRetryAndSession(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int, sessionID string) error {
	msgID := uuid.New().String()
	return SendMessageWithRetryAndRecipient(w, message, key, msgID, ttl, maxRetries, sessionID, "")
}

// SendMessageWithRetryAndRecipient sends message with intelligent retry, session isolation, and recipient
func SendMessageWithRetryAndRecipient(w io.Writer, message string, key []byte, msgID string, ttl int, maxRetries int, sessionID string, recipient string) error {
	if maxRetries < 0 {
		maxRetries = 3
	}

	var lastErr error
	backoff := 100 * time.Millisecond

	for i := 0; i <= maxRetries; i++ {
		if err := SendMessageWithRecipient(w, message, key, msgID, ttl, sessionID, recipient); err != nil {
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

// ReceiveMessageWithTimeout receives message with configurable timeout (legacy interface)
func ReceiveMessageWithTimeout(r io.Reader, key []byte, timeout time.Duration) (string, error) {
	msg, _, _, err := ReceiveMessageWithTimeoutAndDetails(r, key, timeout, "")
	return msg, err
}

// ReceiveMessageWithTimeoutAndSession receives message with configurable timeout and session isolation (legacy interface)
func ReceiveMessageWithTimeoutAndSession(r io.Reader, key []byte, timeout time.Duration, sessionID string) (string, error) {
	msg, _, _, err := ReceiveMessageWithTimeoutAndDetails(r, key, timeout, sessionID)
	return msg, err
}

// ReceiveMessageWithTimeoutAndDetails receives message with configurable timeout and full details
func ReceiveMessageWithTimeoutAndDetails(r io.Reader, key []byte, timeout time.Duration, sessionID string) (message string, msgID string, recipient string, err error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	type result struct {
		message   string
		msgID     string
		recipient string
		err       error
	}

	resultChan := make(chan result, 1)

	go func() {
		defer close(resultChan)
		msg, id, recip, err := ReceiveMessageWithDetails(r, key, sessionID)
		resultChan <- result{message: msg, msgID: id, recipient: recip, err: err}
	}()

	select {
	case res := <-resultChan:
		return res.message, res.msgID, res.recipient, res.err
	case <-time.After(timeout):
		return "", "", "", fmt.Errorf("receive timeout after %v", timeout)
	}
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

// ValidateRecipient validates a recipient identifier
func ValidateRecipient(recipient string) error {
	type RecipientStruct struct {
		Recipient string `validate:"recipient"`
	}

	return validate.Struct(&RecipientStruct{Recipient: recipient})
}

// ValidateMessageID validates a message UUID
func ValidateMessageID(msgID string) error {
	type MessageIDStruct struct {
		MessageID string `validate:"required,uuid_string"`
	}

	return validate.Struct(&MessageIDStruct{MessageID: msgID})
}

// GenerateMessageID generates a new UUID for messages
func GenerateMessageID() string {
	return uuid.New().String()
}

// ParseMessageID validates and parses a message ID
func ParseMessageID(msgID string) (uuid.UUID, error) {
	return uuid.Parse(msgID)
}

// RegisterCustomValidation allows registering additional custom validations
func RegisterCustomValidation(tag string, fn validator.Func) error {
	return validate.RegisterValidation(tag, fn)
}

// GetValidatorInstance returns the global validator instance for advanced usage
func GetValidatorInstance() *validator.Validate {
	return validate
}

// Utility functions for recipient management

// IsRecipientValid checks if a recipient identifier is valid
func IsRecipientValid(recipient string) bool {
	return ValidateRecipient(recipient) == nil
}

// NormalizeRecipient normalizes a recipient identifier (lowercase, trim spaces)
func NormalizeRecipient(recipient string) string {
	if recipient == "" {
		return ""
	}

	// Simple normalization - can be extended
	normalized := strings.ToLower(strings.TrimSpace(recipient))

	// Validate normalized result
	if !IsRecipientValid(normalized) {
		return ""
	}

	return normalized
}

// IsBroadcastMessage checks if a message is a broadcast (no specific recipient)
func IsBroadcastMessage(recipient string) bool {
	return recipient == ""
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
	jsonOverhead := 200                                          // Approximate JSON metadata (including UUID, SessionID, Recipient)
	encryptionOverhead := protocolNonceSize + secretbox.Overhead // Nonce + NaCl overhead
	newlineOverhead := 1

	return jsonOverhead + encryptionOverhead + newlineOverhead
}

// Protocol version management

// GetProtocolVersion returns the current protocol version
func GetProtocolVersion() int {
	return protocolVersion
}

// IsVersionSupported checks if a protocol version is supported
func IsVersionSupported(version int) bool {
	// Support versions 1, 2 (legacy) and 3 (current with UUID)
	return version >= 1 && version <= 3
}

// GetVersionFeatures returns features available in a specific version
func GetVersionFeatures(version int) map[string]bool {
	features := map[string]bool{
		"encryption":        false,
		"session_id":        false,
		"recipient":         false,
		"uuid_id":           false,
		"replay_protection": false,
	}

	switch version {
	case 1:
		features["encryption"] = true
		features["replay_protection"] = true
	case 2:
		features["encryption"] = true
		features["session_id"] = true
		features["replay_protection"] = true
	case 3:
		features["encryption"] = true
		features["session_id"] = true
		features["recipient"] = true
		features["uuid_id"] = true
		features["replay_protection"] = true
	}

	return features
}

// Configuration and constants for new features

// GetMaxRecipientLength returns the maximum allowed recipient length
func GetMaxRecipientLength() int {
	return maxRecipientLen
}

// GetReplayWindow returns the current replay protection window
func GetReplayWindow() time.Duration {
	return replayWindow
}

// GetMaxHistoryEntries returns the maximum number of history entries per session
func GetMaxHistoryEntries() int {
	return maxHistoryEntries
}

// Migration utilities for upgrading from sequence-based to UUID-based messages

// MigrationStats represents statistics about migration process
type MigrationStats struct {
	ProcessedMessages int       `json:"processed_messages"`
	MigratedMessages  int       `json:"migrated_messages"`
	FailedMessages    int       `json:"failed_messages"`
	StartTime         time.Time `json:"start_time"`
	EndTime           time.Time `json:"end_time"`
	Duration          string    `json:"duration"`
}

// BackwardCompatibilityMode enables handling of old sequence-based messages
var BackwardCompatibilityMode = false

// EnableBackwardCompatibility enables backward compatibility with sequence-based messages
func EnableBackwardCompatibility() {
	BackwardCompatibilityMode = true
}

// DisableBackwardCompatibility disables backward compatibility
func DisableBackwardCompatibility() {
	BackwardCompatibilityMode = false
}

// IsBackwardCompatibilityEnabled returns the current backward compatibility state
func IsBackwardCompatibilityEnabled() bool {
	return BackwardCompatibilityMode
}
