package rocher

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	maxTTL            = 86400
	protocolVersion   = 3
	protocolNonceSize = 24
	protocolKeySize   = 32
	maxRecipientLen   = 64
)

var (
	ErrInvalidMessage = errors.New("invalid message")
	validate          = validator.New()
)

func init() {
	validate.RegisterValidation("safe_string", validateSafeString)
	validate.RegisterValidation("session_id", validateSessionID)
	validate.RegisterValidation("uuid_string", validateUUIDString)
	validate.RegisterValidation("recipient", validateRecipient)
}

// Envelope message structure
type Envelope struct {
	ID        string `json:"id" validate:"required,uuid_string"`
	Timestamp int64  `json:"ts" validate:"required"`
	TTL       int    `json:"ttl,omitempty" validate:"min=0,max=86400"`
	Data      string `json:"data" validate:"required,max=1048576,safe_string"`
	Version   int    `json:"v" validate:"eq=3"`
	SessionID string `json:"sid,omitempty" validate:"session_id"`
	Recipient string `json:"recipient,omitempty" validate:"recipient"`
}

// Custom validation functions
func validateSafeString(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	for _, r := range str {
		if r == 0 || (r > 0 && r < 32 && r != '\n' && r != '\r' && r != '\t') {
			return false
		}
	}
	return true
}

func validateSessionID(fl validator.FieldLevel) bool {
	sessionID := fl.Field().String()
	if len(sessionID) == 0 {
		return true
	}
	if len(sessionID) > 64 {
		return false
	}
	for _, r := range sessionID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
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
	if len(recipient) == 0 {
		return true
	}
	if len(recipient) > maxRecipientLen {
		return false
	}
	for _, r := range recipient {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '@' || r == '.') {
			return false
		}
	}
	return true
}

// ValidateEnvelope validates an envelope
func ValidateEnvelope(env *Envelope) error {
	return validate.Struct(env)
}

// SendMessage sends encrypted message with all features
func SendMessage(w io.Writer, message string, key []byte, msgID string, ttl int, sessionID string, recipient string) error {
	if w == nil || len(message) == 0 || len(key) < 32 {
		return ErrInvalidMessage
	}

	if ttl < 0 || ttl > maxTTL {
		ttl = 0
	}

	if msgID == "" {
		msgID = uuid.New().String()
	}

	if _, err := uuid.Parse(msgID); err != nil {
		return ErrInvalidMessage
	}

	envelope := Envelope{
		ID:        msgID,
		Timestamp: time.Now().Unix(),
		TTL:       ttl,
		Data:      message,
		Version:   protocolVersion,
		SessionID: sessionID,
		Recipient: recipient,
	}

	if err := ValidateEnvelope(&envelope); err != nil {
		return ErrInvalidMessage
	}

	envJSON, err := json.Marshal(envelope)
	if err != nil {
		return ErrInvalidMessage
	}

	if len(envJSON) > messageSizeLimit/2 {
		return ErrInvalidMessage
	}

	// Derive key and encrypt
	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return ErrInvalidMessage
	}
	defer secureZeroMemory(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	var nonce [protocolNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrInvalidMessage
	}

	encrypted := secretbox.Seal(nil, envJSON, &nonce, &secretKey)

	finalMessage := make([]byte, protocolNonceSize+len(encrypted)+1)
	copy(finalMessage[:protocolNonceSize], nonce[:])
	copy(finalMessage[protocolNonceSize:protocolNonceSize+len(encrypted)], encrypted)
	finalMessage[len(finalMessage)-1] = '\n'

	if len(finalMessage) > messageSizeLimit {
		return ErrInvalidMessage
	}

	_, err = w.Write(finalMessage)
	secureZeroMemory(secretKey[:])
	secureZeroMemory(nonce[:])
	secureZeroMemory(finalMessage)

	return err
}

// ReceiveMessage receives and decrypts message
func ReceiveMessage(r io.Reader, key []byte, sessionID string) (message string, msgID string, recipient string, err error) {
	if r == nil || len(key) < 32 {
		return "", "", "", ErrInvalidMessage
	}

	reader := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", "", ErrInvalidMessage
	}

	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}

	if line == "" {
		return "", "", "", ErrInvalidMessage
	}

	data := []byte(line)
	defer secureZeroMemory(data)

	if len(data) < protocolNonceSize+secretbox.Overhead {
		return "", "", "", ErrInvalidMessage
	}

	protocolKey, err := deriveKeyWithContext(key, "protocol", protocolKeySize)
	if err != nil {
		return "", "", "", ErrInvalidMessage
	}
	defer secureZeroMemory(protocolKey)

	var secretKey [protocolKeySize]byte
	copy(secretKey[:], protocolKey)

	var nonce [protocolNonceSize]byte
	copy(nonce[:], data[:protocolNonceSize])
	ciphertext := data[protocolNonceSize:]

	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return "", "", "", ErrInvalidMessage
	}
	defer secureZeroMemory(decrypted)

	var envelope Envelope
	if err := json.Unmarshal(decrypted, &envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	if err := ValidateEnvelope(&envelope); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	if err := validateMessageWithSession(envelope, sessionID); err != nil {
		return "", "", "", ErrInvalidMessage
	}

	secureZeroMemory(secretKey[:])
	secureZeroMemory(nonce[:])

	return envelope.Data, envelope.ID, envelope.Recipient, nil
}

// validateMessageWithSession validates message with session isolation
func validateMessageWithSession(env Envelope, expectedSessionID string) error {
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

	if timeDiff > windowSeconds || timeDiff < -5 {
		return ErrInvalidMessage
	}

	// TTL check
	if env.TTL > 0 && now > env.Timestamp+int64(env.TTL) {
		return ErrInvalidMessage
	}

	// Anti-replay check
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

// Utility functions
func GenerateMessageID() string {
	return uuid.New().String()
}

func ValidateRecipient(recipient string) error {
	type RecipientStruct struct {
		Recipient string `validate:"recipient"`
	}
	return validate.Struct(&RecipientStruct{Recipient: recipient})
}

func ValidateMessageID(msgID string) error {
	type MessageIDStruct struct {
		MessageID string `validate:"required,uuid_string"`
	}
	return validate.Struct(&MessageIDStruct{MessageID: msgID})
}

func IsRecipientValid(recipient string) bool {
	return ValidateRecipient(recipient) == nil
}

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

func IsBroadcastMessage(recipient string) bool {
	return recipient == ""
}

func EstimateMessageOverhead(messageSize int) int {
	jsonOverhead := 200
	encryptionOverhead := protocolNonceSize + secretbox.Overhead
	newlineOverhead := 1
	return jsonOverhead + encryptionOverhead + newlineOverhead
}

func GetProtocolVersion() int {
	return protocolVersion
}

func IsVersionSupported(version int) bool {
	return version >= 1 && version <= 3
}

func GetMaxRecipientLength() int {
	return maxRecipientLen
}

func GetReplayWindow() time.Duration {
	return replayWindow
}

func GetMaxHistoryEntries() int {
	return maxHistoryEntries
}
