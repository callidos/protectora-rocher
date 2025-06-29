package rocher

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionAlreadyExists = errors.New("session already exists")
	ErrMaxSessionsReached   = errors.New("maximum sessions reached")
	ErrInvalidSessionID     = errors.New("invalid session ID")
)

// Session represents a complete secure connection with key exchange and encrypted channel
type Session struct {
	channel   *SecureChannel
	sessionID string
	isClient  bool
	startTime time.Time
	mutex     sync.RWMutex

	localPrivKey ed25519.PrivateKey
	localPubKey  ed25519.PublicKey
	remotePubKey ed25519.PublicKey
	sharedSecret [32]byte

	isEstablished bool
	isClosed      bool
	metadata      map[string]interface{}
}

// SessionConfig configuration for establishing a session
type SessionConfig struct {
	IsClient bool
	Timeout  time.Duration
	Metadata map[string]interface{}
}

// NewSession creates a new session with key exchange and secure channel
func NewSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	if err := validateEd25519Keys(localPrivKey, remotePubKey); err != nil {
		return nil, fmt.Errorf("invalid keys: %w", err)
	}

	localPubKey := localPrivKey.Public().(ed25519.PublicKey)

	session := &Session{
		sessionID:    generateSessionID(),
		isClient:     config.IsClient,
		startTime:    time.Now(),
		localPrivKey: localPrivKey,
		localPubKey:  localPubKey,
		remotePubKey: remotePubKey,
		metadata:     config.Metadata,
	}

	if err := session.performKeyExchange(conn, config.Timeout); err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	channel, err := NewSecureChannel(conn, session.sharedSecret, config.IsClient)
	if err != nil {
		session.cleanup()
		return nil, fmt.Errorf("secure channel creation failed: %w", err)
	}

	session.channel = channel
	session.isEstablished = true

	return session, nil
}

// performKeyExchange performs hybrid key exchange with timeout
func (s *Session) performKeyExchange(conn io.ReadWriter, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("key exchange panic: %v", r)
			}
		}()

		var result *KeyExchangeResult
		var err error

		if s.isClient {
			exchanger := NewClientKeyExchanger()
			result, err = exchanger.PerformExchange(conn, s.localPrivKey, s.remotePubKey)
		} else {
			exchanger := NewServerKeyExchanger()
			result, err = exchanger.PerformExchange(conn, s.localPrivKey, s.remotePubKey)
		}

		if err != nil {
			done <- err
			return
		}

		if result.Error != nil {
			done <- result.Error
			return
		}

		if err := ValidateKeyExchangeResult(result); err != nil {
			done <- err
			return
		}

		s.sharedSecret = result.SharedSecret
		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return NewTimeoutError("Key exchange timeout", nil)
	}
}

// SendMessage sends a secure message
func (s *Session) SendMessage(message []byte) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isEstablished {
		return errors.New("session not established")
	}

	if s.isClosed {
		return errors.New("session closed")
	}

	return s.channel.SendMessage(message)
}

// ReceiveMessage receives a secure message
func (s *Session) ReceiveMessage() ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isEstablished {
		return nil, errors.New("session not established")
	}

	if s.isClosed {
		return nil, errors.New("session closed")
	}

	return s.channel.ReceiveMessage()
}

// SendMessageWithTimeout sends a message with timeout
func (s *Session) SendMessageWithTimeout(message []byte, timeout time.Duration) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isEstablished {
		return errors.New("session not established")
	}

	if s.isClosed {
		return errors.New("session closed")
	}

	return s.channel.SendMessageWithTimeout(message, timeout)
}

// ReceiveMessageWithTimeout receives a message with timeout
func (s *Session) ReceiveMessageWithTimeout(timeout time.Duration) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isEstablished {
		return nil, errors.New("session not established")
	}

	if s.isClosed {
		return nil, errors.New("session closed")
	}

	return s.channel.ReceiveMessageWithTimeout(timeout)
}

// Close closes the session and cleans up resources
func (s *Session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isClosed {
		return nil
	}

	s.isClosed = true
	s.isEstablished = false

	if s.channel != nil {
		s.channel.Close()
	}

	s.cleanup()
	return nil
}

// cleanup cleans up sensitive session data
func (s *Session) cleanup() {
	secureZeroMemory(s.sharedSecret[:])
	if s.localPrivKey != nil {
		secureZeroMemory(s.localPrivKey)
	}
}

// IsActive returns session state
func (s *Session) IsActive() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isEstablished && !s.isClosed
}

// IsEstablished returns if session is established
func (s *Session) IsEstablished() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isEstablished
}

// GetSessionID returns session identifier
func (s *Session) GetSessionID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sessionID
}

// GetLocalPublicKey returns local public key
func (s *Session) GetLocalPublicKey() ed25519.PublicKey {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.localPubKey
}

// GetRemotePublicKey returns remote public key
func (s *Session) GetRemotePublicKey() ed25519.PublicKey {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.remotePubKey
}

// IsIdle checks if session is inactive
func (s *Session) IsIdle(maxIdleTime time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.channel == nil {
		return true
	}

	return s.channel.IsIdle(maxIdleTime)
}

// GetStats returns session statistics
func (s *Session) GetStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := map[string]interface{}{
		"session_id":     s.sessionID,
		"is_client":      s.isClient,
		"is_established": s.isEstablished,
		"is_active":      s.isEstablished && !s.isClosed,
		"start_time":     s.startTime,
		"duration":       time.Since(s.startTime),
		"metadata":       s.metadata,
	}

	if s.channel != nil {
		channelStats := s.channel.GetStats()
		stats["channel"] = channelStats
	}

	return stats
}

// SetMetadata sets session metadata
func (s *Session) SetMetadata(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.metadata == nil {
		s.metadata = make(map[string]interface{})
	}
	s.metadata[key] = value
}

// GetMetadata gets session metadata
func (s *Session) GetMetadata(key string) (interface{}, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.metadata == nil {
		return nil, false
	}

	value, exists := s.metadata[key]
	return value, exists
}

// SessionManager manages multiple sessions - thread-safe with sync.Map
type SessionManager struct {
	sessions sync.Map
	maxSize  int32
	current  int32
	stats    SessionManagerStats
	mu       sync.RWMutex
}

type SessionManagerStats struct {
	TotalCreated  uint64
	TotalClosed   uint64
	CurrentActive int
	LastCleanup   time.Time
	CleanupCount  uint64
}

// NewSessionManager creates a new session manager
func NewSessionManager(maxSessions int) *SessionManager {
	if maxSessions <= 0 {
		maxSessions = 100
	}

	return &SessionManager{
		maxSize: int32(maxSessions),
		stats: SessionManagerStats{
			LastCleanup: time.Now(),
		},
	}
}

// CreateSession creates and registers a new session
func (sm *SessionManager) CreateSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	if sm.current >= sm.maxSize {
		return nil, ErrMaxSessionsReached
	}

	session, err := NewSession(conn, localPrivKey, remotePubKey, config)
	if err != nil {
		return nil, err
	}

	sessionID := session.GetSessionID()
	_, loaded := sm.sessions.LoadOrStore(sessionID, session)

	if !loaded {
		sm.current++
		sm.mu.Lock()
		sm.stats.TotalCreated++
		sm.stats.CurrentActive = int(sm.current)
		sm.mu.Unlock()
	}

	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	value, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, ErrSessionNotFound
	}
	return value.(*Session), nil
}

// RemoveSession removes a session
func (sm *SessionManager) RemoveSession(sessionID string) error {
	value, loaded := sm.sessions.LoadAndDelete(sessionID)
	if !loaded {
		return ErrSessionNotFound
	}

	if session, ok := value.(*Session); ok {
		session.Close()
	}

	sm.current--
	sm.mu.Lock()
	sm.stats.TotalClosed++
	sm.stats.CurrentActive = int(sm.current)
	sm.mu.Unlock()

	return nil
}

// ListSessions returns list of active session IDs
func (sm *SessionManager) ListSessions() []string {
	var sessionIDs []string
	sm.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok && session.IsActive() {
			sessionIDs = append(sessionIDs, key.(string))
		}
		return true
	})
	return sessionIDs
}

// CleanupIdleSessions cleans up idle sessions
func (sm *SessionManager) CleanupIdleSessions(maxIdleTime time.Duration) int {
	var toRemove []string

	sm.sessions.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		session := value.(*Session)

		if !session.IsActive() || session.IsIdle(maxIdleTime) {
			toRemove = append(toRemove, sessionID)
		}
		return true
	})

	for _, sessionID := range toRemove {
		sm.RemoveSession(sessionID)
	}

	sm.mu.Lock()
	sm.stats.LastCleanup = time.Now()
	sm.stats.CleanupCount++
	sm.mu.Unlock()

	return len(toRemove)
}

// GetStats returns manager statistics
func (sm *SessionManager) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	activeCount := 0
	idleCount := 0
	clientCount := 0
	serverCount := 0

	sm.sessions.Range(func(key, value interface{}) bool {
		session := value.(*Session)
		if session.IsActive() {
			activeCount++
			if session.isClient {
				clientCount++
			} else {
				serverCount++
			}
		}
		if session.IsIdle(5 * time.Minute) {
			idleCount++
		}
		return true
	})

	return map[string]interface{}{
		"total_sessions":  int(sm.current),
		"active_sessions": activeCount,
		"idle_sessions":   idleCount,
		"client_sessions": clientCount,
		"server_sessions": serverCount,
		"max_sessions":    sm.maxSize,
		"total_created":   sm.stats.TotalCreated,
		"total_closed":    sm.stats.TotalClosed,
		"last_cleanup":    sm.stats.LastCleanup,
		"cleanup_count":   sm.stats.CleanupCount,
		"algorithms":      []string{"Kyber768", "X25519", "Ed25519", "NaCl-secretbox"},
	}
}

// Convenience functions for creating sessions
func CreateClientSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: true,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, localPrivKey, serverPubKey, config)
}

func CreateServerSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: false,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, localPrivKey, clientPubKey, config)
}

// EstablishSecureConnection - Main simplified entry point
func EstablishSecureConnection(conn io.ReadWriter, isClient bool, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: isClient,
		Timeout:  30 * time.Second,
		Metadata: map[string]interface{}{
			"established_at": time.Now(),
			"version":        "rocher-v2",
		},
	}

	session, err := NewSession(conn, localPrivKey, remotePubKey, config)
	if err != nil {
		return nil, fmt.Errorf("failed to establish secure connection: %w", err)
	}

	return session, nil
}

// SessionHealthCheck checks session health
func (s *Session) SessionHealthCheck() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if !s.isEstablished {
		return errors.New("session not established")
	}

	if s.isClosed {
		return errors.New("session closed")
	}

	if s.channel == nil {
		return errors.New("secure channel is nil")
	}

	if ValidateSecureChannel(s.channel) != nil {
		return errors.New("channel validation failed")
	}

	if time.Since(s.startTime) > 24*time.Hour {
		return errors.New("session too old (>24h)")
	}

	return nil
}

// SessionPingPong performs ping-pong test for connectivity
func (s *Session) SessionPingPong(timeout time.Duration) error {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	pingMessage := []byte("PING")
	pongMessage := []byte("PONG")

	if s.isClient {
		if err := s.SendMessageWithTimeout(pingMessage, timeout); err != nil {
			return fmt.Errorf("ping send failed: %w", err)
		}

		response, err := s.ReceiveMessageWithTimeout(timeout)
		if err != nil {
			return fmt.Errorf("pong receive failed: %w", err)
		}

		if string(response) != "PONG" {
			return fmt.Errorf("unexpected response: %s", string(response))
		}
	} else {
		message, err := s.ReceiveMessageWithTimeout(timeout)
		if err != nil {
			return fmt.Errorf("ping receive failed: %w", err)
		}

		if string(message) != "PING" {
			return fmt.Errorf("unexpected message: %s", string(message))
		}

		if err := s.SendMessageWithTimeout(pongMessage, timeout); err != nil {
			return fmt.Errorf("pong send failed: %w", err)
		}
	}

	return nil
}
