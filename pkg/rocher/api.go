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

// Session représente une connexion sécurisée complète avec échange de clés et canal chiffré
type Session struct {
	channel   *SecureChannel
	sessionID string
	isClient  bool
	startTime time.Time
	mutex     sync.RWMutex

	// Clés utilisées pour l'établissement
	localPrivKey ed25519.PrivateKey
	localPubKey  ed25519.PublicKey
	remotePubKey ed25519.PublicKey
	sharedSecret [32]byte

	// État de la session
	isEstablished bool
	isClosed      bool

	// Métadonnées
	metadata map[string]interface{}
}

// SessionConfig configuration pour établir une session
type SessionConfig struct {
	IsClient bool
	Timeout  time.Duration
	Metadata map[string]interface{}
}

// NewSession crée une nouvelle session avec échange de clés et canal sécurisé
func NewSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Valider les clés
	if err := validateEd25519Keys(localPrivKey, remotePubKey); err != nil {
		return nil, fmt.Errorf("invalid keys: %w", err)
	}

	// Extraire la clé publique locale
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

	// Effectuer l'échange de clés
	if err := session.performKeyExchange(conn, config.Timeout); err != nil {
		return nil, fmt.Errorf("key exchange failed: %w", err)
	}

	// Créer le canal sécurisé
	channel, err := NewSecureChannel(conn, session.sharedSecret, config.IsClient)
	if err != nil {
		session.cleanup()
		return nil, fmt.Errorf("secure channel creation failed: %w", err)
	}

	session.channel = channel
	session.isEstablished = true

	return session, nil
}

// performKeyExchange effectue l'échange de clés hybride avec timeout
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

		// Valider le résultat
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

// SendMessage envoie un message sécurisé
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

// ReceiveMessage reçoit un message sécurisé
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

// SendMessageWithTimeout envoie un message avec timeout
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

// ReceiveMessageWithTimeout reçoit un message avec timeout
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

// Close ferme la session et nettoie les ressources
func (s *Session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isClosed {
		return nil
	}

	s.isClosed = true
	s.isEstablished = false

	// Fermer le canal sécurisé
	if s.channel != nil {
		s.channel.Close()
	}

	// Nettoyer les données sensibles
	s.cleanup()

	return nil
}

// cleanup nettoie les données sensibles de la session
func (s *Session) cleanup() {
	// Nettoyer le secret partagé
	secureZeroMemory(s.sharedSecret[:])

	// Nettoyer la clé privée (copie)
	if s.localPrivKey != nil {
		secureZeroMemory(s.localPrivKey)
	}
}

// IsActive retourne l'état de la session
func (s *Session) IsActive() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isEstablished && !s.isClosed
}

// IsEstablished retourne si la session est établie
func (s *Session) IsEstablished() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isEstablished
}

// GetSessionID retourne l'identifiant de session
func (s *Session) GetSessionID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sessionID
}

// GetLocalPublicKey retourne la clé publique locale
func (s *Session) GetLocalPublicKey() ed25519.PublicKey {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.localPubKey
}

// GetRemotePublicKey retourne la clé publique distante
func (s *Session) GetRemotePublicKey() ed25519.PublicKey {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.remotePubKey
}

// IsIdle vérifie si la session est inactive
func (s *Session) IsIdle(maxIdleTime time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.channel == nil {
		return true
	}

	return s.channel.IsIdle(maxIdleTime)
}

// GetStats retourne les statistiques de la session
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

	// Ajouter les stats du canal si disponible
	if s.channel != nil {
		channelStats := s.channel.GetStats()
		stats["channel"] = channelStats
	}

	return stats
}

// SetMetadata définit des métadonnées pour la session
func (s *Session) SetMetadata(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.metadata == nil {
		s.metadata = make(map[string]interface{})
	}
	s.metadata[key] = value
}

// GetMetadata récupère une métadonnée
func (s *Session) GetMetadata(key string) (interface{}, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if s.metadata == nil {
		return nil, false
	}

	value, exists := s.metadata[key]
	return value, exists
}

// SessionManager gère plusieurs sessions simultanées
type SessionManager struct {
	sessions    map[string]*Session
	maxSessions int
	mutex       sync.RWMutex
	stats       SessionManagerStats
}

// SessionManagerStats statistiques du gestionnaire de sessions
type SessionManagerStats struct {
	TotalCreated  uint64
	TotalClosed   uint64
	CurrentActive int
	LastCleanup   time.Time
	CleanupCount  uint64
}

// NewSessionManager crée un nouveau gestionnaire de sessions
func NewSessionManager(maxSessions int) *SessionManager {
	if maxSessions <= 0 {
		maxSessions = 100
	}

	return &SessionManager{
		sessions:    make(map[string]*Session),
		maxSessions: maxSessions,
		stats: SessionManagerStats{
			LastCleanup: time.Now(),
		},
	}
}

// CreateSession crée et enregistre une nouvelle session
func (sm *SessionManager) CreateSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Vérifier les limites
	if len(sm.sessions) >= sm.maxSessions {
		return nil, ErrMaxSessionsReached
	}

	// Créer la session
	session, err := NewSession(conn, localPrivKey, remotePubKey, config)
	if err != nil {
		return nil, err
	}

	// Enregistrer la session
	sessionID := session.GetSessionID()
	sm.sessions[sessionID] = session
	sm.stats.TotalCreated++
	sm.stats.CurrentActive = len(sm.sessions)

	return session, nil
}

// GetSession récupère une session par ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// RemoveSession supprime une session
func (sm *SessionManager) RemoveSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	// Fermer la session
	session.Close()

	// Supprimer de la map
	delete(sm.sessions, sessionID)
	sm.stats.TotalClosed++
	sm.stats.CurrentActive = len(sm.sessions)

	return nil
}

// ListSessions retourne la liste des IDs de sessions actives
func (sm *SessionManager) ListSessions() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessionIDs := make([]string, 0, len(sm.sessions))
	for sessionID, session := range sm.sessions {
		if session.IsActive() {
			sessionIDs = append(sessionIDs, sessionID)
		}
	}

	return sessionIDs
}

// CleanupIdleSessions nettoie les sessions inactives
func (sm *SessionManager) CleanupIdleSessions(maxIdleTime time.Duration) int {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	var toRemove []string

	for sessionID, session := range sm.sessions {
		if !session.IsActive() || session.IsIdle(maxIdleTime) {
			toRemove = append(toRemove, sessionID)
		}
	}

	// Supprimer les sessions inactives
	for _, sessionID := range toRemove {
		if session, exists := sm.sessions[sessionID]; exists {
			session.Close()
			delete(sm.sessions, sessionID)
			sm.stats.TotalClosed++
		}
	}

	sm.stats.CurrentActive = len(sm.sessions)
	sm.stats.LastCleanup = time.Now()
	sm.stats.CleanupCount++

	return len(toRemove)
}

// CloseAllSessions ferme toutes les sessions
func (sm *SessionManager) CloseAllSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for sessionID, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, sessionID)
		sm.stats.TotalClosed++
	}

	sm.stats.CurrentActive = 0
}

// GetStats retourne les statistiques du gestionnaire
func (sm *SessionManager) GetStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	activeCount := 0
	idleCount := 0
	clientCount := 0
	serverCount := 0

	for _, session := range sm.sessions {
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
	}

	return map[string]interface{}{
		"total_sessions":  len(sm.sessions),
		"active_sessions": activeCount,
		"idle_sessions":   idleCount,
		"client_sessions": clientCount,
		"server_sessions": serverCount,
		"max_sessions":    sm.maxSessions,
		"total_created":   sm.stats.TotalCreated,
		"total_closed":    sm.stats.TotalClosed,
		"last_cleanup":    sm.stats.LastCleanup,
		"cleanup_count":   sm.stats.CleanupCount,
		"algorithms":      []string{"Kyber768", "X25519", "Ed25519", "NaCl-secretbox"},
	}
}

// GetDetailedStats retourne les statistiques détaillées de toutes les sessions
func (sm *SessionManager) GetDetailedStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessionsStats := make(map[string]interface{})
	for sessionID, session := range sm.sessions {
		sessionsStats[sessionID] = session.GetStats()
	}

	generalStats := sm.GetStats()
	generalStats["sessions_detail"] = sessionsStats

	return generalStats
}

// Fonctions de commodité pour créer des sessions

// CreateClientSession crée une session côté client
func CreateClientSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: true,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, localPrivKey, serverPubKey, config)
}

// CreateServerSession crée une session côté serveur
func CreateServerSession(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: false,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, localPrivKey, clientPubKey, config)
}

// CreateSessionWithTimeout crée une session avec timeout personnalisé
func CreateSessionWithTimeout(conn io.ReadWriter, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, isClient bool, timeout time.Duration) (*Session, error) {
	config := SessionConfig{
		IsClient: isClient,
		Timeout:  timeout,
	}
	return NewSession(conn, localPrivKey, remotePubKey, config)
}

// EstablishSecureConnection - Point d'entrée principal simplifié
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

// ValidateSessionConfig valide une configuration de session
func ValidateSessionConfig(config SessionConfig) error {
	if config.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}

	if config.Timeout > 5*time.Minute {
		return errors.New("timeout too long (max 5 minutes)")
	}

	if config.Timeout == 0 {
		return errors.New("timeout cannot be zero")
	}

	return nil
}

// SessionInfo contient les informations essentielles d'une session
type SessionInfo struct {
	SessionID     string                 `json:"session_id"`
	IsClient      bool                   `json:"is_client"`
	IsActive      bool                   `json:"is_active"`
	IsEstablished bool                   `json:"is_established"`
	StartTime     time.Time              `json:"start_time"`
	Duration      time.Duration          `json:"duration"`
	LocalPubKey   []byte                 `json:"local_public_key"`
	RemotePubKey  []byte                 `json:"remote_public_key"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// GetSessionInfo retourne les informations de base d'une session
func (s *Session) GetSessionInfo() SessionInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return SessionInfo{
		SessionID:     s.sessionID,
		IsClient:      s.isClient,
		IsActive:      s.IsActive(),
		IsEstablished: s.isEstablished,
		StartTime:     s.startTime,
		Duration:      time.Since(s.startTime),
		LocalPubKey:   s.localPubKey,
		RemotePubKey:  s.remotePubKey,
		Metadata:      s.metadata,
	}
}

// SessionHealthCheck vérifie la santé d'une session
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

	// Vérifier l'état du canal
	if err := ValidateSecureChannel(s.channel); err != nil {
		return fmt.Errorf("channel validation failed: %w", err)
	}

	// Vérifier si la session n'est pas trop ancienne
	if time.Since(s.startTime) > 24*time.Hour {
		return errors.New("session too old (>24h)")
	}

	return nil
}

// RekeySession effectue un nouveau key exchange pour renouveler les clés
func (s *Session) RekeySession(conn io.ReadWriter, timeout time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isEstablished || s.isClosed {
		return errors.New("session not active")
	}

	// Effectuer un nouvel échange de clés
	if err := s.performKeyExchange(conn, timeout); err != nil {
		return fmt.Errorf("rekey failed: %w", err)
	}

	// Renouveler les clés du canal
	if err := s.channel.RekeyChannel(s.sharedSecret); err != nil {
		return fmt.Errorf("channel rekey failed: %w", err)
	}

	return nil
}

// EstimateSessionOverhead estime l'overhead total d'une session
func EstimateSessionOverhead() map[string]interface{} {
	keyExchangeOverhead := EstimateKeyExchangeOverhead()
	channelOverhead := EstimateChannelOverhead()

	// Extraire les valeurs directement (map[string]int)
	totalHandshake := keyExchangeOverhead["total_round_trip"]
	perMessage := channelOverhead["per_message_total"]

	return map[string]interface{}{
		"key_exchange":     keyExchangeOverhead,
		"channel":          channelOverhead,
		"session_metadata": 200, // Estimation pour les métadonnées de session
		"total_handshake":  totalHandshake,
		"per_message":      perMessage,
		"establishment":    totalHandshake + 200,
	}
}

// SessionPingPong effectue un test de ping-pong pour vérifier la connectivité
func (s *Session) SessionPingPong(timeout time.Duration) error {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	pingMessage := []byte("PING")
	pongMessage := []byte("PONG")

	if s.isClient {
		// Client envoie PING
		if err := s.SendMessageWithTimeout(pingMessage, timeout); err != nil {
			return fmt.Errorf("ping send failed: %w", err)
		}

		// Client reçoit PONG
		response, err := s.ReceiveMessageWithTimeout(timeout)
		if err != nil {
			return fmt.Errorf("pong receive failed: %w", err)
		}

		if string(response) != "PONG" {
			return fmt.Errorf("unexpected response: %s", string(response))
		}
	} else {
		// Serveur reçoit PING
		message, err := s.ReceiveMessageWithTimeout(timeout)
		if err != nil {
			return fmt.Errorf("ping receive failed: %w", err)
		}

		if string(message) != "PING" {
			return fmt.Errorf("unexpected message: %s", string(message))
		}

		// Serveur envoie PONG
		if err := s.SendMessageWithTimeout(pongMessage, timeout); err != nil {
			return fmt.Errorf("pong send failed: %w", err)
		}
	}

	return nil
}

// Global session manager instance
var defaultSessionManager *SessionManager
var sessionManagerOnce sync.Once

// GetDefaultSessionManager retourne l'instance globale du gestionnaire de sessions
func GetDefaultSessionManager() *SessionManager {
	sessionManagerOnce.Do(func() {
		defaultSessionManager = NewSessionManager(100)
	})
	return defaultSessionManager
}

// RegisterSession enregistre une session dans le gestionnaire global
func RegisterSession(session *Session) error {
	sm := GetDefaultSessionManager()
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sessionID := session.GetSessionID()
	if _, exists := sm.sessions[sessionID]; exists {
		return ErrSessionAlreadyExists
	}

	if len(sm.sessions) >= sm.maxSessions {
		return ErrMaxSessionsReached
	}

	sm.sessions[sessionID] = session
	sm.stats.CurrentActive = len(sm.sessions)
	return nil
}

// UnregisterSession désenregistre une session du gestionnaire global
func UnregisterSession(sessionID string) error {
	sm := GetDefaultSessionManager()
	return sm.RemoveSession(sessionID)
}

// FindSessionByPublicKey trouve une session par clé publique distante
func (sm *SessionManager) FindSessionByPublicKey(remotePubKey ed25519.PublicKey) *Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	for _, session := range sm.sessions {
		if constantTimeCompare(session.GetRemotePublicKey(), remotePubKey) {
			return session
		}
	}

	return nil
}
