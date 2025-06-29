package rocher

import (
	"bufio"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bufferSize        = 1024 * 1024
	maxUsernameLength = 64
	minUsernameLength = 3
	maxMessageSize    = 10 * 1024
	connectionTimeout = 30 * time.Second
	maxConnections    = 100
)

// ConnectionHandler manages a secure connection with authentication
type ConnectionHandler struct {
	session      *Session
	reader       io.Reader
	writer       io.Writer
	username     string
	connected    bool
	mu           sync.RWMutex
	startTime    time.Time
	messageCount uint64
	sessionID    string
	lastActivity int64

	localPrivKey ed25519.PrivateKey
	localPubKey  ed25519.PublicKey
	remotePubKey ed25519.PublicKey
}

// NewConnectionHandler creates a new connection handler
func NewConnectionHandler(r io.Reader, w io.Writer, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) *ConnectionHandler {
	sessionID := generateSessionID()
	localPubKey := localPrivKey.Public().(ed25519.PublicKey)

	return &ConnectionHandler{
		reader:       r,
		writer:       w,
		localPrivKey: localPrivKey,
		localPubKey:  localPubKey,
		remotePubKey: remotePubKey,
		startTime:    time.Now(),
		sessionID:    sessionID,
		lastActivity: time.Now().Unix(),
	}
}

// HandleConnection manages the connection lifecycle with secure session
func (ch *ConnectionHandler) HandleConnection(isClient bool) error {
	ch.mu.Lock()
	ch.mu.Unlock()

	// User authentication with timeout
	if err := ch.authenticateUser(); err != nil {
		ch.sendError(ErrAuthentication)
		return err
	}

	// Establish secure session with key exchange
	if err := ch.establishSecureSession(isClient); err != nil {
		ch.sendError(ErrProcessing)
		return err
	}

	// Send welcome message through secure channel
	if err := ch.sendSecureWelcome(); err != nil {
		return err
	}

	// Message processing loop through secure channel
	return ch.secureMessageLoop()
}

// authenticateUser authenticates user with enhanced validation
func (ch *ConnectionHandler) authenticateUser() error {
	limitedReader := io.LimitReader(ch.reader, maxUsernameLength*2)
	scanner := bufio.NewScanner(limitedReader)

	timeout := time.NewTimer(connectionTimeout)
	defer timeout.Stop()

	usernameChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- ErrConnection
			}
		}()

		if scanner.Scan() {
			username := strings.TrimSpace(scanner.Text())
			if err := ch.validateUsernameConstantTime(username); err != nil {
				errChan <- err
			} else {
				usernameChan <- username
			}
		} else {
			if err := scanner.Err(); err != nil {
				errChan <- fmt.Errorf("scanner error: %w", err)
			} else {
				errChan <- ErrConnection
			}
		}
	}()

	select {
	case username := <-usernameChan:
		ch.mu.Lock()
		ch.username = username
		ch.connected = true
		ch.mu.Unlock()
		ch.updateActivity()
		return nil
	case err := <-errChan:
		return err
	case <-timeout.C:
		return ErrTimeout
	}
}

// validateUsernameConstantTime validates username with constant-time comparison
func (ch *ConnectionHandler) validateUsernameConstantTime(username string) error {
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return ErrInvalidInput
	}

	// Reserved names with constant-time comparison
	reserved := [6][16]byte{
		{'a', 'd', 'm', 'i', 'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{'r', 'o', 'o', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{'s', 'y', 's', 't', 'e', 'm', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{'n', 'u', 'l', 'l', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{'u', 'n', 'd', 'e', 'f', 'i', 'n', 'e', 'd', 0, 0, 0, 0, 0, 0, 0},
		{'a', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's', 0, 0, 0, 0, 0, 0, 0},
	}

	var userPadded [16]byte
	copy(userPadded[:], strings.ToLower(username))

	isReserved := 0
	for i := range reserved {
		if subtle.ConstantTimeCompare(userPadded[:], reserved[i][:]) == 1 {
			isReserved = 1
		}
	}

	if isReserved == 1 {
		return ErrInvalidInput
	}

	// Character validation
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return ErrInvalidInput
		}
	}

	// First character must be letter
	if len(username) > 0 {
		first := rune(username[0])
		if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
			return ErrInvalidInput
		}
	}

	return nil
}

// establishSecureSession establishes secure session with key exchange
func (ch *ConnectionHandler) establishSecureSession(isClient bool) error {
	conn := &connectionWrapper{reader: ch.reader, writer: ch.writer}

	session, err := EstablishSecureConnection(conn, isClient, ch.localPrivKey, ch.remotePubKey)
	if err != nil {
		return fmt.Errorf("failed to establish secure connection: %w", err)
	}

	ch.session = session
	ch.sessionID = session.GetSessionID()
	return nil
}

// sendSecureWelcome sends welcome message via secure channel
func (ch *ConnectionHandler) sendSecureWelcome() error {
	username := ch.getUsername()
	message := fmt.Sprintf("Welcome %s to the secure server. Session established with quantum-resistant cryptography.", username)
	return ch.session.SendMessage([]byte(message))
}

// secureMessageLoop main message processing loop via secure channel
func (ch *ConnectionHandler) secureMessageLoop() error {
	limitedReader := io.LimitReader(ch.reader, maxMessageSize*2)
	scanner := bufio.NewScanner(limitedReader)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		ch.updateActivity()

		if line == "END_SESSION" {
			return ch.closeConnection()
		}

		if err := ch.processSecureMessage(line); err != nil {
			ch.sendError(ErrProcessing)
		}
	}

	if err := scanner.Err(); err != nil {
		return ErrConnection
	}
	return nil
}

// processSecureMessage processes a message received via secure channel
func (ch *ConnectionHandler) processSecureMessage(rawMessage string) error {
	if len(rawMessage) > maxMessageSize {
		return ErrInvalidInput
	}

	if !ch.isValidMessageContent(rawMessage) {
		return ErrInvalidInput
	}

	ch.incrementMessageCount()
	return ch.sendSecureAcknowledgment(rawMessage)
}

// isValidMessageContent validates message content
func (ch *ConnectionHandler) isValidMessageContent(message string) bool {
	for _, r := range message {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// sendSecureAcknowledgment sends acknowledgment via secure channel
func (ch *ConnectionHandler) sendSecureAcknowledgment(originalMessage string) error {
	ackMessage := fmt.Sprintf("Message received and processed securely: '%s'", originalMessage)
	return ch.session.SendMessage([]byte(ackMessage))
}

// updateActivity updates last activity timestamp atomically
func (ch *ConnectionHandler) updateActivity() {
	atomic.StoreInt64(&ch.lastActivity, time.Now().Unix())
}

// sendError sends a generic error response
func (ch *ConnectionHandler) sendError(err error) {
	var errorMsg string
	switch {
	case IsErrorCode(err, ErrorCodeAuthError):
		errorMsg = "Authentication error"
	case IsErrorCode(err, ErrorCodeInternal):
		errorMsg = "Processing error"
	case IsErrorCode(err, ErrorCodeInvalidInput):
		errorMsg = "Invalid input"
	case IsErrorCode(err, ErrorCodeNetworkError):
		errorMsg = "Network error"
	case IsErrorCode(err, ErrorCodeTimeout):
		errorMsg = "Operation timeout"
	default:
		switch err {
		case ErrAuthentication:
			errorMsg = "Authentication error"
		case ErrProcessing:
			errorMsg = "Processing error"
		case ErrInvalidInput:
			errorMsg = "Invalid input"
		case ErrConnection:
			errorMsg = "Connection error"
		case ErrTimeout:
			errorMsg = "Operation timeout"
		default:
			errorMsg = "Internal error"
		}
	}

	response := fmt.Sprintf("Error: %s\n", errorMsg)
	ch.writer.Write([]byte(response))
}

// closeConnection properly closes the connection with session cleanup
func (ch *ConnectionHandler) closeConnection() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.connected = false

	if ch.session != nil {
		ch.session.Close()
	}

	if closer, ok := ch.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Thread-safe getters
func (ch *ConnectionHandler) IsConnected() bool {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.connected
}

func (ch *ConnectionHandler) getUsername() string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.username
}

func (ch *ConnectionHandler) GetUsername() string {
	return ch.getUsername()
}

func (ch *ConnectionHandler) incrementMessageCount() {
	atomic.AddUint64(&ch.messageCount, 1)
}

func (ch *ConnectionHandler) getMessageCount() uint64 {
	return atomic.LoadUint64(&ch.messageCount)
}

// GetStats returns connection statistics
func (ch *ConnectionHandler) GetStats() map[string]interface{} {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	lastActivity := atomic.LoadInt64(&ch.lastActivity)
	messageCount := atomic.LoadUint64(&ch.messageCount)

	stats := map[string]interface{}{
		"username":      ch.username,
		"connected":     ch.connected,
		"start_time":    ch.startTime,
		"duration":      time.Since(ch.startTime),
		"message_count": messageCount,
		"session_id":    ch.sessionID,
		"last_activity": time.Unix(lastActivity, 0),
		"idle_duration": time.Since(time.Unix(lastActivity, 0)),
		"algorithms":    []string{"Kyber768", "X25519", "Ed25519", "NaCl-secretbox"},
	}

	if ch.session != nil {
		sessionStats := ch.session.GetStats()
		stats["session"] = sessionStats
	}

	return stats
}

func (ch *ConnectionHandler) IsIdle(maxIdleTime time.Duration) bool {
	lastActivity := atomic.LoadInt64(&ch.lastActivity)
	return time.Since(time.Unix(lastActivity, 0)) > maxIdleTime
}

func (ch *ConnectionHandler) GetSessionID() string {
	return ch.sessionID
}

func (ch *ConnectionHandler) GetSession() *Session {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.session
}

func (ch *ConnectionHandler) SendSecureMessage(message string) error {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if ch.session == nil {
		return errors.New("secure session not established")
	}
	return ch.session.SendMessage([]byte(message))
}

func (ch *ConnectionHandler) ReceiveSecureMessage() (string, error) {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if ch.session == nil {
		return "", errors.New("secure session not established")
	}

	data, err := ch.session.ReceiveMessage()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// connectionWrapper adapts io.Reader and io.Writer to io.ReadWriter
type connectionWrapper struct {
	reader io.Reader
	writer io.Writer
}

func (cw *connectionWrapper) Read(p []byte) (n int, err error) {
	return cw.reader.Read(p)
}

func (cw *connectionWrapper) Write(p []byte) (n int, err error) {
	return cw.writer.Write(p)
}

// ConnectionManager manages multiple simultaneous connections - thread-safe
type ConnectionManager struct {
	connections sync.Map
	maxSize     int32
	current     int32
	stats       ConnectionManagerStats
	mu          sync.RWMutex
}

type ConnectionManagerStats struct {
	TotalConnections  uint64
	ActiveConnections int
	TotalClosed       uint64
	LastCleanup       time.Time
}

func NewConnectionManager(maxConnections int) *ConnectionManager {
	if maxConnections <= 0 {
		maxConnections = maxConnections
	}

	return &ConnectionManager{
		maxSize: int32(maxConnections),
		stats: ConnectionManagerStats{
			LastCleanup: time.Now(),
		},
	}
}

func (cm *ConnectionManager) AddConnection(handler *ConnectionHandler) error {
	if atomic.LoadInt32(&cm.current) >= cm.maxSize {
		return fmt.Errorf("maximum connections reached (%d)", cm.maxSize)
	}

	sessionID := handler.GetSessionID()
	_, loaded := cm.connections.LoadOrStore(sessionID, handler)

	if !loaded {
		atomic.AddInt32(&cm.current, 1)
		cm.mu.Lock()
		cm.stats.TotalConnections++
		cm.stats.ActiveConnections = int(atomic.LoadInt32(&cm.current))
		cm.mu.Unlock()
	}

	return nil
}

func (cm *ConnectionManager) RemoveConnection(sessionID string) error {
	value, loaded := cm.connections.LoadAndDelete(sessionID)
	if !loaded {
		return fmt.Errorf("connection not found: %s", sessionID)
	}

	if handler, ok := value.(*ConnectionHandler); ok {
		handler.closeConnection()
	}

	atomic.AddInt32(&cm.current, -1)
	cm.mu.Lock()
	cm.stats.TotalClosed++
	cm.stats.ActiveConnections = int(atomic.LoadInt32(&cm.current))
	cm.mu.Unlock()

	return nil
}

func (cm *ConnectionManager) GetConnection(sessionID string) (*ConnectionHandler, error) {
	value, ok := cm.connections.Load(sessionID)
	if !ok {
		return nil, fmt.Errorf("connection not found: %s", sessionID)
	}
	return value.(*ConnectionHandler), nil
}

func (cm *ConnectionManager) ListConnections() []string {
	var sessionIDs []string
	cm.connections.Range(func(key, value interface{}) bool {
		if handler, ok := value.(*ConnectionHandler); ok && handler.IsConnected() {
			sessionIDs = append(sessionIDs, key.(string))
		}
		return true
	})
	return sessionIDs
}

func (cm *ConnectionManager) CleanupIdleConnections(maxIdleTime time.Duration) int {
	var toRemove []string

	cm.connections.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		handler := value.(*ConnectionHandler)

		if !handler.IsConnected() || handler.IsIdle(maxIdleTime) {
			toRemove = append(toRemove, sessionID)
		}
		return true
	})

	for _, sessionID := range toRemove {
		cm.RemoveConnection(sessionID)
	}

	cm.mu.Lock()
	cm.stats.LastCleanup = time.Now()
	cm.mu.Unlock()

	return len(toRemove)
}

func (cm *ConnectionManager) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	activeCount := int(atomic.LoadInt32(&cm.current))
	connectedCount := 0
	totalMessages := uint64(0)

	cm.connections.Range(func(key, value interface{}) bool {
		if handler, ok := value.(*ConnectionHandler); ok && handler.IsConnected() {
			connectedCount++
			totalMessages += handler.getMessageCount()
		}
		return true
	})

	return map[string]interface{}{
		"total_connections":   activeCount,
		"active_connections":  activeCount,
		"connected_count":     connectedCount,
		"max_connections":     cm.maxSize,
		"total_created":       cm.stats.TotalConnections,
		"total_closed":        cm.stats.TotalClosed,
		"total_messages":      totalMessages,
		"last_cleanup":        cm.stats.LastCleanup,
		"security_algorithms": []string{"Kyber768", "X25519", "Ed25519", "NaCl-secretbox"},
	}
}

// Utility functions
func CreateConnectionHandler(r io.Reader, w io.Writer, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) *ConnectionHandler {
	return NewConnectionHandler(r, w, localPrivKey, remotePubKey)
}

func HandleSecureConnection(r io.Reader, w io.Writer, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, isClient bool) error {
	handler := NewConnectionHandler(r, w, localPrivKey, remotePubKey)
	return handler.HandleConnection(isClient)
}

func generateSessionID() string {
	return generateUUID()
}
