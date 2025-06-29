package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	channelKeySize    = 32
	channelNonceSize  = 24
	maxChannelMessage = 65535
	channelOverhead   = secretbox.Overhead
)

var (
	ErrChannelNotInitialized = errors.New("secure channel not initialized")
	ErrChannelClosed         = errors.New("secure channel closed")
	ErrInvalidNonce          = errors.New("invalid nonce sequence")
	ErrMessageTooLarge       = errors.New("message too large for secure channel")
)

// SecureChannel manages bidirectional encrypted communication with NaCl secretbox
type SecureChannel struct {
	sendKey [channelKeySize]byte
	recvKey [channelKeySize]byte

	sendNonce uint64
	recvNonce uint64

	conn io.ReadWriter

	isInitialized bool
	isClosed      bool
	mu            sync.RWMutex

	isClient   bool
	sessionID  string
	startTime  time.Time
	lastActive time.Time

	messagesSent     uint64
	messagesReceived uint64
	bytesSent        uint64
	bytesReceived    uint64
}

// NewSecureChannel creates a new secure channel from shared secret
func NewSecureChannel(conn io.ReadWriter, sharedSecret [32]byte, isClient bool) (*SecureChannel, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	sessionID := generateSessionID()

	sc := &SecureChannel{
		conn:          conn,
		isClient:      isClient,
		sessionID:     sessionID,
		startTime:     time.Now(),
		lastActive:    time.Now(),
		isInitialized: false,
		isClosed:      false,
	}

	if err := sc.deriveChannelKeys(sharedSecret); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	sc.isInitialized = true
	return sc, nil
}

// deriveChannelKeys derives separate send and receive keys
func (sc *SecureChannel) deriveChannelKeys(sharedSecret [32]byte) error {
	salt := []byte("protectora-rocher-channel-salt-v2")

	var sendInfo, recvInfo []byte
	if sc.isClient {
		sendInfo = []byte("protectora-rocher-client-send-v2")
		recvInfo = []byte("protectora-rocher-client-recv-v2")
	} else {
		sendInfo = []byte("protectora-rocher-server-send-v2")
		recvInfo = []byte("protectora-rocher-server-recv-v2")
	}

	// Derive send key
	hkdfSend := hkdf.New(sha256.New, sharedSecret[:], salt, sendInfo)
	if _, err := io.ReadFull(hkdfSend, sc.sendKey[:]); err != nil {
		return fmt.Errorf("send key derivation failed: %w", err)
	}

	// Derive receive key
	hkdfRecv := hkdf.New(sha256.New, sharedSecret[:], salt, recvInfo)
	if _, err := io.ReadFull(hkdfRecv, sc.recvKey[:]); err != nil {
		return fmt.Errorf("recv key derivation failed: %w", err)
	}

	// Verify keys are not zero
	if isAllZeros(sc.sendKey[:]) || isAllZeros(sc.recvKey[:]) {
		return errors.New("derived keys are zero")
	}

	return nil
}

// SendMessage encrypts and sends a message thread-safely
func (sc *SecureChannel) SendMessage(plaintext []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized {
		return ErrChannelNotInitialized
	}

	if sc.isClosed {
		return ErrChannelClosed
	}

	if len(plaintext) > maxChannelMessage {
		return ErrMessageTooLarge
	}

	// Prepare nonce with sequential counter
	var nonce [channelNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], sc.sendNonce)

	// Add entropy in remaining nonce bytes
	if _, err := rand.Read(nonce[8:16]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt with NaCl secretbox
	ciphertext := secretbox.Seal(nil, plaintext, &nonce, &sc.sendKey)

	// Message format: nonce (24 bytes) + ciphertext
	message := make([]byte, channelNonceSize+len(ciphertext))
	copy(message[:channelNonceSize], nonce[:])
	copy(message[channelNonceSize:], ciphertext)

	if err := sc.sendRawMessage(message); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	// Update statistics
	sc.sendNonce++
	sc.messagesSent++
	sc.bytesSent += uint64(len(plaintext))
	sc.lastActive = time.Now()

	return nil
}

// ReceiveMessage receives and decrypts a message thread-safely
func (sc *SecureChannel) ReceiveMessage() ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized {
		return nil, ErrChannelNotInitialized
	}

	if sc.isClosed {
		return nil, ErrChannelClosed
	}

	message, err := sc.receiveRawMessage()
	if err != nil {
		return nil, fmt.Errorf("receive failed: %w", err)
	}

	if len(message) < channelNonceSize+channelOverhead {
		return nil, ErrInvalidMessage
	}

	// Extract nonce and ciphertext
	var nonce [channelNonceSize]byte
	copy(nonce[:], message[:channelNonceSize])
	ciphertext := message[channelNonceSize:]

	// Verify nonce sequence
	receivedSeq := binary.LittleEndian.Uint64(nonce[:8])
	if receivedSeq != sc.recvNonce {
		return nil, ErrInvalidNonce
	}

	// Decrypt with NaCl secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &sc.recvKey)
	if !ok {
		return nil, ErrInvalidMessage
	}

	// Update statistics
	sc.recvNonce++
	sc.messagesReceived++
	sc.bytesReceived += uint64(len(plaintext))
	sc.lastActive = time.Now()

	return plaintext, nil
}

// SendMessageWithTimeout sends a message with timeout
func (sc *SecureChannel) SendMessageWithTimeout(plaintext []byte, timeout time.Duration) error {
	if timeout <= 0 {
		return sc.SendMessage(plaintext)
	}

	done := make(chan error, 1)
	go func() {
		done <- sc.SendMessage(plaintext)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return NewTimeoutError("Send message timeout", nil)
	}
}

// ReceiveMessageWithTimeout receives a message with timeout
func (sc *SecureChannel) ReceiveMessageWithTimeout(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		return sc.ReceiveMessage()
	}

	type result struct {
		data []byte
		err  error
	}

	done := make(chan result, 1)
	go func() {
		data, err := sc.ReceiveMessage()
		done <- result{data: data, err: err}
	}()

	select {
	case res := <-done:
		return res.data, res.err
	case <-time.After(timeout):
		return nil, NewTimeoutError("Receive message timeout", nil)
	}
}

// sendRawMessage sends raw message with length prefix
func (sc *SecureChannel) sendRawMessage(data []byte) error {
	// Format: length (4 bytes) + data
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))

	if _, err := sc.conn.Write(lengthBytes); err != nil {
		return err
	}

	totalWritten := 0
	for totalWritten < len(data) {
		n, err := sc.conn.Write(data[totalWritten:])
		if err != nil {
			return err
		}
		totalWritten += n
	}

	return nil
}

// receiveRawMessage receives raw message with length prefix
func (sc *SecureChannel) receiveRawMessage() ([]byte, error) {
	// Read length
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(sc.conn, lengthBytes); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBytes)

	// Validate length
	if length == 0 {
		return nil, ErrInvalidMessage
	}
	if length > maxChannelMessage+channelNonceSize+channelOverhead {
		return nil, ErrMessageTooLarge
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(sc.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// Close closes secure channel and cleans up resources
func (sc *SecureChannel) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.isClosed {
		return nil
	}

	// Securely clean keys
	secureZeroMemory(sc.sendKey[:])
	secureZeroMemory(sc.recvKey[:])

	sc.isClosed = true
	sc.isInitialized = false

	if closer, ok := sc.conn.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// IsActive returns channel state
func (sc *SecureChannel) IsActive() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.isInitialized && !sc.isClosed
}

// IsIdle checks if channel is idle for given time
func (sc *SecureChannel) IsIdle(maxIdleTime time.Duration) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return time.Since(sc.lastActive) > maxIdleTime
}

// GetSessionID returns session identifier
func (sc *SecureChannel) GetSessionID() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.sessionID
}

// GetStats returns channel statistics
func (sc *SecureChannel) GetStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return map[string]interface{}{
		"session_id":        sc.sessionID,
		"is_client":         sc.isClient,
		"is_active":         sc.isInitialized && !sc.isClosed,
		"start_time":        sc.startTime,
		"last_active":       sc.lastActive,
		"duration":          time.Since(sc.startTime),
		"idle_time":         time.Since(sc.lastActive),
		"messages_sent":     sc.messagesSent,
		"messages_received": sc.messagesReceived,
		"bytes_sent":        sc.bytesSent,
		"bytes_received":    sc.bytesReceived,
		"send_nonce":        sc.sendNonce,
		"recv_nonce":        sc.recvNonce,
		"cipher":            "NaCl-secretbox",
		"max_message_size":  maxChannelMessage,
	}
}

// RekeyChannel performs channel re-keying for enhanced security
func (sc *SecureChannel) RekeyChannel(newSharedSecret [32]byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized || sc.isClosed {
		return ErrChannelNotInitialized
	}

	// Clean old keys
	secureZeroMemory(sc.sendKey[:])
	secureZeroMemory(sc.recvKey[:])

	// Derive new keys
	if err := sc.deriveChannelKeys(newSharedSecret); err != nil {
		return fmt.Errorf("rekey failed: %w", err)
	}

	// Reset nonces
	sc.sendNonce = 0
	sc.recvNonce = 0
	sc.lastActive = time.Now()

	return nil
}

// EstimateChannelOverhead estimates secure channel overhead
func EstimateChannelOverhead() map[string]int {
	return map[string]int{
		"nonce_size":         channelNonceSize,
		"secretbox_overhead": channelOverhead,
		"length_prefix":      4,
		"per_message_total":  channelNonceSize + channelOverhead + 4,
		"max_message_size":   maxChannelMessage,
		"key_size":           channelKeySize,
	}
}

// ValidateSecureChannel validates secure channel state
func ValidateSecureChannel(sc *SecureChannel) error {
	if sc == nil {
		return errors.New("secure channel is nil")
	}

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if !sc.isInitialized {
		return ErrChannelNotInitialized
	}

	if sc.isClosed {
		return ErrChannelClosed
	}

	if sc.conn == nil {
		return errors.New("connection is nil")
	}

	if isAllZeros(sc.sendKey[:]) || isAllZeros(sc.recvKey[:]) {
		return errors.New("encryption keys are zero")
	}

	return nil
}
