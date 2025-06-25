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

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	AUDIO_DATA = 0
	CONTROL    = 1
	END_CALL   = 2

	maxAudioSize   = 32 * 1024 // 32KB max per message
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

// AudioMessage represents an audio message
type AudioMessage struct {
	Type      uint8
	Timestamp int64
	Data      []byte
}

// AudioProtocol manages secure audio communication with NaCl secretbox
type AudioProtocol struct {
	conn     io.ReadWriter
	key      [audioKeySize]byte
	isActive bool
	mutex    sync.RWMutex
	stopChan chan struct{}
}

// NewAudioProtocol creates a new audio protocol with shared session key
func NewAudioProtocol(conn io.ReadWriter, sessionKey []byte) (*AudioProtocol, error) {
	if conn == nil {
		return nil, errors.New("connection required")
	}
	if len(sessionKey) < 32 {
		return nil, errors.New("session key too short")
	}

	// Key derivation specific for audio
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

	fmt.Printf("[INFO] Audio protocol initialized - cipher: NaCl-secretbox\n")

	return ap, nil
}

// StartCall starts a secure audio call
func (ap *AudioProtocol) StartCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if ap.isActive {
		return ErrCallInProgress
	}

	ap.isActive = true
	ap.stopChan = make(chan struct{})

	// Send call start signal
	if err := ap.sendControlMessage("START_CALL"); err != nil {
		ap.isActive = false
		return fmt.Errorf("failed to start call: %w", err)
	}

	fmt.Printf("[INFO] Audio call started - cipher: NaCl-secretbox\n")
	return nil
}

// SendAudio sends encrypted audio data
func (ap *AudioProtocol) SendAudio(audioData []byte) error {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return ErrNoActiveCall
	}

	if len(audioData) > maxAudioSize {
		fmt.Printf("[WARNING] Audio data too large - size: %d, max_size: %d\n",
			len(audioData), maxAudioSize)
		return ErrAudioTooLarge
	}

	message := &AudioMessage{
		Type:      AUDIO_DATA,
		Timestamp: time.Now().UnixNano(),
		Data:      audioData,
	}

	if err := ap.sendMessage(message); err != nil {
		fmt.Printf("[ERROR] Failed to send audio data - data_size: %d, error: %v\n",
			len(audioData), err)
		return err
	}

	fmt.Printf("[DEBUG] Audio data sent - size: %d\n", len(audioData))
	return nil
}

// ReceiveAudio receives and decrypts audio data
func (ap *AudioProtocol) ReceiveAudio() ([]byte, error) {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()

	if !ap.isActive {
		return nil, ErrNoActiveCall
	}

	message, err := ap.receiveMessage()
	if err != nil {
		fmt.Printf("[ERROR] Failed to receive audio message - error: %v\n", err)
		return nil, err
	}

	if message.Type != AUDIO_DATA {
		fmt.Printf("[WARNING] Unexpected message type received - expected: %d, received: %d\n",
			AUDIO_DATA, message.Type)
		return nil, fmt.Errorf("unexpected message type: %d", message.Type)
	}

	fmt.Printf("[DEBUG] Audio data received - size: %d\n", len(message.Data))
	return message.Data, nil
}

// StopCall stops the audio call
func (ap *AudioProtocol) StopCall() error {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()

	if !ap.isActive {
		return ErrNoActiveCall
	}

	// Send end call signal
	if err := ap.sendControlMessage("END_CALL"); err != nil {
		fmt.Printf("[WARNING] Failed to send end call signal - error: %v\n", err)
	}

	ap.isActive = false
	close(ap.stopChan)

	fmt.Printf("[INFO] Audio call stopped\n")
	return nil
}

// IsActive returns the call state
func (ap *AudioProtocol) IsActive() bool {
	ap.mutex.RLock()
	defer ap.mutex.RUnlock()
	return ap.isActive
}

// sendMessage sends an encrypted audio message with NaCl secretbox
func (ap *AudioProtocol) sendMessage(message *AudioMessage) error {
	// Serialize message
	serialized, err := ap.serializeMessage(message)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Generate nonce
	var nonce [audioNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt with NaCl secretbox
	encrypted := secretbox.Seal(nil, serialized, &nonce, &ap.key)

	// Final format: size + nonce + encrypted data
	finalData := make([]byte, 4+audioNonceSize+len(encrypted))
	binary.BigEndian.PutUint32(finalData[:4], uint32(audioNonceSize+len(encrypted)))
	copy(finalData[4:4+audioNonceSize], nonce[:])
	copy(finalData[4+audioNonceSize:], encrypted)

	// Send
	if _, err := ap.conn.Write(finalData); err != nil {
		return ErrConnectionLost
	}

	return nil
}

// receiveMessage receives and decrypts an audio message
func (ap *AudioProtocol) receiveMessage() (*AudioMessage, error) {
	// Read message size
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(ap.conn, sizeBuf); err != nil {
		return nil, ErrConnectionLost
	}

	size := binary.BigEndian.Uint32(sizeBuf)
	if size > maxAudioSize*2 { // Margin for encryption metadata
		fmt.Printf("[WARNING] Received message too large - size: %d, max_size: %d\n",
			size, maxAudioSize*2)
		return nil, ErrInvalidAudio
	}

	// Read complete message
	messageBuf := make([]byte, size)
	if _, err := io.ReadFull(ap.conn, messageBuf); err != nil {
		return nil, ErrConnectionLost
	}

	// Extract nonce
	if len(messageBuf) < audioNonceSize {
		return nil, ErrInvalidAudio
	}

	var nonce [audioNonceSize]byte
	copy(nonce[:], messageBuf[:audioNonceSize])
	encrypted := messageBuf[audioNonceSize:]

	// Decrypt with NaCl secretbox
	decrypted, ok := secretbox.Open(nil, encrypted, &nonce, &ap.key)
	if !ok {
		fmt.Printf("[ERROR] Audio message decryption failed\n")
		return nil, fmt.Errorf("decryption failed")
	}

	// Deserialize
	message, err := ap.deserializeMessage(decrypted)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return message, nil
}

// sendControlMessage sends a control message
func (ap *AudioProtocol) sendControlMessage(control string) error {
	message := &AudioMessage{
		Type:      CONTROL,
		Timestamp: time.Now().UnixNano(),
		Data:      []byte(control),
	}

	fmt.Printf("[DEBUG] Sending control message - control: %s\n", control)
	return ap.sendMessage(message)
}

// serializeMessage serializes a message
func (ap *AudioProtocol) serializeMessage(message *AudioMessage) ([]byte, error) {
	// Simple format: Type(1) + Timestamp(8) + DataLength(4) + Data
	buf := make([]byte, 1+8+4+len(message.Data))

	buf[0] = message.Type
	binary.BigEndian.PutUint64(buf[1:9], uint64(message.Timestamp))
	binary.BigEndian.PutUint32(buf[9:13], uint32(len(message.Data)))
	copy(buf[13:], message.Data)

	return buf, nil
}

// deserializeMessage deserializes a message
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

// GetStats returns audio session statistics
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

// Enhanced audio protocol with metrics and monitoring

// AudioMetrics tracks audio session metrics
type AudioMetrics struct {
	StartTime        time.Time
	BytesSent        uint64
	BytesReceived    uint64
	MessagesSent     uint64
	MessagesReceived uint64
	Errors           uint64
	mu               sync.RWMutex
}

// NewAudioMetrics creates new audio metrics
func NewAudioMetrics() *AudioMetrics {
	return &AudioMetrics{
		StartTime: time.Now(),
	}
}

// RecordSent records sent data
func (am *AudioMetrics) RecordSent(bytes int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.BytesSent += uint64(bytes)
	am.MessagesSent++
}

// RecordReceived records received data
func (am *AudioMetrics) RecordReceived(bytes int) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.BytesReceived += uint64(bytes)
	am.MessagesReceived++
}

// RecordError records an error
func (am *AudioMetrics) RecordError() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.Errors++
}

// GetStats returns metrics statistics
func (am *AudioMetrics) GetStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	duration := time.Since(am.StartTime)
	return map[string]interface{}{
		"start_time":        am.StartTime,
		"duration":          duration,
		"bytes_sent":        am.BytesSent,
		"bytes_received":    am.BytesReceived,
		"messages_sent":     am.MessagesSent,
		"messages_received": am.MessagesReceived,
		"errors":            am.Errors,
		"throughput_sent":   float64(am.BytesSent) / duration.Seconds(),
		"throughput_recv":   float64(am.BytesReceived) / duration.Seconds(),
	}
}

// Enhanced AudioProtocol with metrics
type EnhancedAudioProtocol struct {
	*AudioProtocol
	metrics *AudioMetrics
}

// NewEnhancedAudioProtocol creates enhanced audio protocol with metrics
func NewEnhancedAudioProtocol(conn io.ReadWriter, sessionKey []byte) (*EnhancedAudioProtocol, error) {
	base, err := NewAudioProtocol(conn, sessionKey)
	if err != nil {
		return nil, err
	}

	return &EnhancedAudioProtocol{
		AudioProtocol: base,
		metrics:       NewAudioMetrics(),
	}, nil
}

// SendAudio sends audio with metrics tracking
func (eap *EnhancedAudioProtocol) SendAudio(audioData []byte) error {
	err := eap.AudioProtocol.SendAudio(audioData)
	if err != nil {
		eap.metrics.RecordError()
		fmt.Printf("[ERROR] Enhanced audio send failed - data_size: %d, error: %v\n",
			len(audioData), err)
	} else {
		eap.metrics.RecordSent(len(audioData))
	}
	return err
}

// ReceiveAudio receives audio with metrics tracking
func (eap *EnhancedAudioProtocol) ReceiveAudio() ([]byte, error) {
	data, err := eap.AudioProtocol.ReceiveAudio()
	if err != nil {
		eap.metrics.RecordError()
		fmt.Printf("[ERROR] Enhanced audio receive failed - error: %v\n", err)
	} else {
		eap.metrics.RecordReceived(len(data))
	}
	return data, err
}

// GetEnhancedStats returns enhanced statistics
func (eap *EnhancedAudioProtocol) GetEnhancedStats() map[string]interface{} {
	baseStats := eap.AudioProtocol.GetStats()
	metricsStats := eap.metrics.GetStats()

	// Merge stats
	for k, v := range metricsStats {
		baseStats[k] = v
	}

	return baseStats
}

// Utility functions for audio protocol management

// ValidateAudioData validates audio data before sending
func ValidateAudioData(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty audio data")
	}
	if len(data) > maxAudioSize {
		return ErrAudioTooLarge
	}
	return nil
}

// CreateAudioSession creates a new audio session with logging
func CreateAudioSession(conn io.ReadWriter, sessionKey []byte, enhanced bool) (interface{}, error) {
	fmt.Printf("[INFO] Creating audio session - enhanced: %t\n", enhanced)

	var protocol interface{}
	var err error

	if enhanced {
		protocol, err = NewEnhancedAudioProtocol(conn, sessionKey)
	} else {
		protocol, err = NewAudioProtocol(conn, sessionKey)
	}

	if err != nil {
		fmt.Printf("[ERROR] Failed to create audio session - error: %v\n", err)
	} else {
		fmt.Printf("[INFO] Audio session created successfully\n")
	}

	return protocol, err
}
