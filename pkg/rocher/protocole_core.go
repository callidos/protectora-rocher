package rocher

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	replayWindow      = 30 * time.Second
	messageSizeLimit  = 16 * 1024 * 1024
	maxHistoryEntries = 10000
	cleanupInterval   = 5 * time.Minute
	maxTTL            = 86400 // 24 hours maximum
	protocolVersion   = 3
	protocolNonceSize = 24
	protocolKeySize   = 32
	maxRecipientLen   = 64
)

// Unified error to avoid information leakage
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
	// Allow valid UTF-8 characters, not just ASCII
	for _, r := range str {
		if r == 0 || (r > 0 && r < 32 && r != '\n' && r != '\r' && r != '\t') {
			return false
		}
	}
	return true
}

func validateSessionID(fl validator.FieldLevel) bool {
	sessionID := fl.Field().String()

	// Allow empty SessionID for compatibility
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
	return len(nonce) == 0 || len(nonce) == 16
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

// Envelope message structure with enhanced security
type Envelope struct {
	ID        string `json:"id" validate:"required,uuid_string"`
	Timestamp int64  `json:"ts" validate:"required"`
	TTL       int    `json:"ttl,omitempty" validate:"min=0,max=86400"`
	Data      string `json:"data" validate:"required,max=1048576,safe_string"`
	Version   int    `json:"v" validate:"eq=3"`
	Nonce     []byte `json:"nonce,omitempty" validate:"nonce_size"`
	SessionID string `json:"sid,omitempty" validate:"session_id"`
	Recipient string `json:"recipient,omitempty" validate:"recipient"`
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

// SendMessage sends encrypted message (simplified interface)
func SendMessage(w io.Writer, message string, key []byte, seq uint64, ttl int) error {
	msgID := uuid.New().String()
	return SendMessageWithRecipient(w, message, key, msgID, ttl, "", "")
}

// SendMessageWithSession sends encrypted message with session isolation
func SendMessageWithSession(w io.Writer, message string, key []byte, seq uint64, ttl int, sessionID string) error {
	msgID := uuid.New().String()
	return SendMessageWithRecipient(w, message, key, msgID, ttl, sessionID, "")
}

// SendMessageWithRecipient sends encrypted message with all features
func SendMessageWithRecipient(w io.Writer, message string, key []byte, msgID string, ttl int, sessionID string, recipient string) error {
	if w == nil {
		return errors.New("writer cannot be nil")
	}
	if len(message) == 0 {
		return errors.New("empty message")
	}
	if len(key) < 32 {
		return errors.New("key too short")
	}
	if ttl < 0 || ttl > maxTTL {
		ttl = 0 // Default: no expiration
	}

	// Generate UUID if not provided
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

	// Validate envelope
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
	defer secureZeroMemory(protocolKey)

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

	// Secure cleanup
	secureZeroMemory(secretKey[:])
	secureZeroMemory(nonce[:])
	secureZeroMemory(finalMessage)

	return err
}

// ReceiveMessage receives and decrypts message (simplified interface)
func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	msg, _, _, err := ReceiveMessageWithDetails(r, key, "")
	return msg, err
}

// ReceiveMessageWithSession receives and decrypts message with session isolation
func ReceiveMessageWithSession(r io.Reader, key []byte, sessionID string) (string, error) {
	msg, _, _, err := ReceiveMessageWithDetails(r, key, sessionID)
	return msg, err
}

// ReceiveMessageWithDetails receives and decrypts message with full details
func ReceiveMessageWithDetails(r io.Reader, key []byte, sessionID string) (message string, msgID string, recipient string, err error) {
	if r == nil {
		return "", "", "", errors.New("reader cannot be nil")
	}
	if len(key) < 32 {
		return "", "", "", errors.New("key too short")
	}

	// Read with strict size limit
	reader := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Remove newline
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	if line == "" {
		return "", "", "", ErrInvalidMessage
	}

	// Convert to bytes
	data := []byte(line)
	defer secureZeroMemory(data)

	// Validate minimum size
	if len(data) < protocolNonceSize+secretbox.Overhead {
		return "", "", "", ErrInvalidMessage
	}

	// Derive key for protocol
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return "", "", "", ErrInvalidMessage
	}
	defer secureZeroMemory(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	// Extract components
	var nonce [protocolNonceSize]byte
	copy(nonce[:], data[:protocolNonceSize])
	ciphertext := data[protocolNonceSize:]

	// Decrypt with NaCl secretbox
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return "", "", "", ErrInvalidMessage
	}
	defer secureZeroMemory(decrypted)

	// Deserialize envelope
	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Validate envelope
	if err := ValidateEnvelope(&envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Validate message with session
	if err := validateMessageWithDetailsAndSession(envelope, sessionID); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	// Secure cleanup
	secureZeroMemory(secretKey[:])
	secureZeroMemory(nonce[:])

	return envelope.Data, envelope.ID, envelope.Recipient, nil
}

// validateMessageWithDetailsAndSession validates message integrity and replay protection
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

	// Temporal validation
	if timeDiff > windowSeconds || timeDiff < -5 {
		return ErrInvalidMessage
	}

	// Expiration check (TTL)
	if env.TTL > 0 && now > env.Timestamp+int64(env.TTL) {
		return ErrInvalidMessage
	}

	// Anti-replay verification with session isolation
	sessionKey := env.SessionID
	if sessionKey == "" {
		sessionKey = "default"
	}

	history := getSessionHistory(sessionKey)
	if err := history.CheckAndStore(env.ID, env.Timestamp, env.Recipient, []byte(env.Data)); err != nil {
		return ErrInvalidMessage
	}

	return nil
}

// SendMessageWithRetry sends message with intelligent retry
func SendMessageWithRetry(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int) error {
	msgID := uuid.New().String()
	return SendMessageWithRetryAndRecipient(w, message, key, msgID, ttl, maxRetries, "", "")
}

// SendMessageWithRetryAndSession sends message with retry and session
func SendMessageWithRetryAndSession(w io.Writer, message string, key []byte, seq uint64, ttl int, maxRetries int, sessionID string) error {
	msgID := uuid.New().String()
	return SendMessageWithRetryAndRecipient(w, message, key, msgID, ttl, maxRetries, sessionID, "")
}

// SendMessageWithRetryAndRecipient sends message with full retry support
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
				// Exponential backoff with cryptographically secure jitter
				jitterBytes := make([]byte, 4)
				if _, err := rand.Read(jitterBytes); err == nil {
					// Convert bytes to a value between 0 and backoff/2
					jitterValue := uint32(jitterBytes[0])<<24 | uint32(jitterBytes[1])<<16 | uint32(jitterBytes[2])<<8 | uint32(jitterBytes[3])
					jitter := time.Duration(jitterValue % uint32(backoff/2))
					time.Sleep(backoff + jitter)
				} else {
					// Fallback if crypto/rand fails
					time.Sleep(backoff)
				}
				backoff *= 2
				if backoff > 5*time.Second {
					backoff = 5 * time.Second
				}
				continue
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// ReceiveMessageWithTimeout receives message with timeout
func ReceiveMessageWithTimeout(r io.Reader, key []byte, timeout time.Duration) (string, error) {
	msg, _, _, err := ReceiveMessageWithTimeoutAndDetails(r, key, timeout, "")
	return msg, err
}

// ReceiveMessageWithTimeoutAndSession receives message with timeout and session
func ReceiveMessageWithTimeoutAndSession(r io.Reader, key []byte, timeout time.Duration, sessionID string) (string, error) {
	msg, _, _, err := ReceiveMessageWithTimeoutAndDetails(r, key, timeout, sessionID)
	return msg, err
}

// ReceiveMessageWithTimeoutAndDetails receives message with full timeout support
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

// Helper functions

// GenerateMessageID generates a new UUID for messages
func GenerateMessageID() string {
	return uuid.New().String()
}

// ParseMessageID validates and parses a message ID
func ParseMessageID(msgID string) (uuid.UUID, error) {
	return uuid.Parse(msgID)
}

// ValidateUsername validates username
func ValidateUsername(username string) error {
	type UsernameStruct struct {
		Username string `validate:"required,min=3,max=64,alphanum"`
	}
	return validate.Struct(&UsernameStruct{Username: username})
}

// ValidateSessionIDString validates a session ID
func ValidateSessionIDString(sessionID string) error {
	type SessionStruct struct {
		SessionID string `validate:"session_id"`
	}
	return validate.Struct(&SessionStruct{SessionID: sessionID})
}

// ValidateMessageData validates message content
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

// IsRecipientValid checks if a recipient identifier is valid
func IsRecipientValid(recipient string) bool {
	return ValidateRecipient(recipient) == nil
}

// NormalizeRecipient normalizes a recipient identifier
func NormalizeRecipient(recipient string) string {
	if recipient == "" {
		return ""
	}

	normalized := strings.ToLower(strings.TrimSpace(recipient))
	if !IsRecipientValid(normalized) {
		return ""
	}

	return normalized
}

// IsBroadcastMessage checks if a message is a broadcast
func IsBroadcastMessage(recipient string) bool {
	return recipient == ""
}

// EstimateMessageOverhead estimates protocol overhead
func EstimateMessageOverhead(messageSize int) int {
	jsonOverhead := 200 // JSON metadata including UUID
	encryptionOverhead := protocolNonceSize + secretbox.Overhead
	newlineOverhead := 1
	return jsonOverhead + encryptionOverhead + newlineOverhead
}

// GetProtocolVersion returns the current protocol version
func GetProtocolVersion() int {
	return protocolVersion
}

// IsVersionSupported checks if a protocol version is supported
func IsVersionSupported(version int) bool {
	return version >= 1 && version <= 3
}

// GetMaxRecipientLength returns the maximum recipient length
func GetMaxRecipientLength() int {
	return maxRecipientLen
}

// GetReplayWindow returns the replay protection window
func GetReplayWindow() time.Duration {
	return replayWindow
}

// GetMaxHistoryEntries returns the maximum history entries
func GetMaxHistoryEntries() int {
	return maxHistoryEntries
}
