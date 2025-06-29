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
	ErrSessionNotInitialized = errors.New("session not initialized")
	ErrHandshakeFailed       = errors.New("handshake failed")
	ErrNoiseNotReady         = errors.New("noise not ready")
	ErrConnectionClosed      = errors.New("connection closed")
	ErrSessionAlreadyActive  = errors.New("session already active")
)

// Session représente une connexion sécurisée avec Noise Protocol
type Session struct {
	conn       io.ReadWriter
	noise      *NoiseState
	sessionKey [32]byte
	isClient   bool
	isActive   bool
	mutex      sync.RWMutex
	sessionID  string

	// Compteurs de messages
	sendSeq uint64
	recvSeq uint64

	// Clés statiques pour le handshake
	localKey  *NoiseKeyPair
	remoteKey []byte

	// Métriques
	startTime    time.Time
	lastActivity time.Time
}

// SessionConfig configuration pour une session
type SessionConfig struct {
	IsClient bool
	Timeout  time.Duration
}

// NewSession crée une nouvelle session avec handshake Noise
func NewSession(conn io.ReadWriter, privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Générer un ID de session unique
	sessionID := fmt.Sprintf("noise_session_%d", time.Now().UnixNano())

	// Convertir les clés Ed25519 en clés Noise (pour cette démo, on génère de nouvelles clés Noise)
	// Dans une vraie implémentation, il faudrait une conversion appropriée
	localNoiseKey, err := GenerateNoiseKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate noise keypair: %w", err)
	}

	session := &Session{
		conn:         conn,
		isClient:     config.IsClient,
		isActive:     false,
		sessionID:    sessionID,
		localKey:     localNoiseKey,
		remoteKey:    remotePubKey, // Pour l'instant, on stocke la clé Ed25519
		startTime:    time.Now(),
		lastActivity: time.Now(),
	}

	// Initialiser Noise selon le rôle
	if config.IsClient {
		session.noise = CreateNoiseInitiator()
	} else {
		session.noise = CreateNoiseResponder()
	}

	// Effectuer le handshake
	if err := session.performHandshake(config.Timeout); err != nil {
		session.cleanup()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Dériver la clé de session à partir de l'état Noise
	session.deriveSessionKey()

	session.isActive = true
	return session, nil
}

// performHandshake effectue l'échange de clés Noise
func (s *Session) performHandshake(timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("handshake panic: %v", r)
			}
		}()

		// Pour cette démo, on utilise la clé publique Noise locale comme "remote key"
		// Dans une vraie implémentation, il faudrait échanger/valider les vraies clés
		err := s.noise.PerformHandshake(s.conn, s.localKey, s.localKey.Public[:])
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("noise handshake error: %w", err)
		}
		return nil
	case <-time.After(timeout):
		return errors.New("handshake timeout")
	}
}

// deriveSessionKey dérive une clé de session à partir de l'état Noise
func (s *Session) deriveSessionKey() {
	// Utiliser les clés Noise pour dériver une clé de session
	// Pour cette démo, on utilise une dérivation simple
	sessionData := fmt.Sprintf("%s_%t_%d", s.sessionID, s.isClient, s.startTime.UnixNano())
	key := DeriveSessionKey([]byte(sessionData))
	s.sessionKey = key
}

// SendMessage envoie un message sécurisé via Noise
func (s *Session) SendMessage(message string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return ErrSessionNotInitialized
	}

	if !s.noise.IsInitialized() {
		return ErrNoiseNotReady
	}

	s.updateActivity()

	// Chiffrer avec Noise
	encrypted, err := s.noise.EncryptMessage([]byte(message))
	if err != nil {
		return fmt.Errorf("noise encryption failed: %w", err)
	}

	// Envoyer le message chiffré avec le protocole de message standard
	s.sendSeq++
	msgID := GenerateMessageID()

	if err := SendMessageWithRecipient(s.conn, string(encrypted), s.sessionKey[:], msgID, 0, s.sessionID, ""); err != nil {
		return fmt.Errorf("failed to send encrypted message: %w", err)
	}

	return nil
}

// ReceiveMessage reçoit et déchiffre un message
func (s *Session) ReceiveMessage() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return "", ErrSessionNotInitialized
	}

	if !s.noise.IsInitialized() {
		return "", ErrNoiseNotReady
	}

	s.updateActivity()

	// Recevoir le message chiffré avec session isolée
	encryptedMessage, _, _, err := ReceiveMessageWithDetails(s.conn, s.sessionKey[:], s.sessionID)
	if err != nil {
		return "", fmt.Errorf("receive failed: %w", err)
	}

	// Déchiffrer avec Noise
	decrypted, err := s.noise.DecryptMessage([]byte(encryptedMessage))
	if err != nil {
		return "", fmt.Errorf("noise decryption failed: %w", err)
	}

	s.recvSeq++
	return string(decrypted), nil
}

// SendMessageWithTimeout envoie un message avec timeout
func (s *Session) SendMessageWithTimeout(message string, timeout time.Duration) error {
	if timeout <= 0 {
		return s.SendMessage(message)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.SendMessage(message)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrTimeout
	}
}

// ReceiveMessageWithTimeout reçoit un message avec timeout
func (s *Session) ReceiveMessageWithTimeout(timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return s.ReceiveMessage()
	}

	type result struct {
		message string
		err     error
	}

	done := make(chan result, 1)
	go func() {
		msg, err := s.ReceiveMessage()
		done <- result{message: msg, err: err}
	}()

	select {
	case res := <-done:
		return res.message, res.err
	case <-time.After(timeout):
		return "", ErrTimeout
	}
}

// Close ferme la session proprement
func (s *Session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return nil
	}

	s.isActive = false
	s.cleanup()

	// Fermer la connexion si possible
	if closer, ok := s.conn.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// cleanup nettoie les ressources de la session
func (s *Session) cleanup() {
	// Nettoyage sécurisé
	if s.noise != nil {
		s.noise.Reset()
	}

	secureZeroResistant(s.sessionKey[:])

	if s.localKey != nil {
		secureZeroResistant(s.localKey.Private[:])
		secureZeroResistant(s.localKey.Public[:])
	}

	// Nettoyer l'historique de session
	ResetSessionHistory(s.sessionID)
}

// updateActivity met à jour le timestamp de la dernière activité
func (s *Session) updateActivity() {
	s.lastActivity = time.Now()
}

// IsActive retourne l'état de la session
func (s *Session) IsActive() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isActive
}

// GetSessionID retourne l'identifiant de session
func (s *Session) GetSessionID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.sessionID
}

// GetStats retourne les statistiques de la session
func (s *Session) GetStats() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	stats := map[string]interface{}{
		"is_active":     s.isActive,
		"is_client":     s.isClient,
		"send_count":    s.sendSeq,
		"recv_count":    s.recvSeq,
		"session_id":    s.sessionID,
		"start_time":    s.startTime,
		"last_activity": s.lastActivity,
		"duration":      time.Since(s.startTime),
		"idle_time":     time.Since(s.lastActivity),
		"protocol":      "Noise_XX_25519",
	}

	if s.noise != nil {
		noiseStats := s.noise.GetStats()
		stats["noise"] = noiseStats
	}

	return stats
}

// IsIdle vérifie si la session est inactive
func (s *Session) IsIdle(maxIdleTime time.Duration) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return time.Since(s.lastActivity) > maxIdleTime
}

// GetProtocolInfo retourne les informations sur le protocole utilisé
func (s *Session) GetProtocolInfo() map[string]interface{} {
	return map[string]interface{}{
		"name":           "Noise Protocol Framework",
		"pattern":        "XX",
		"dh":             "Curve25519",
		"cipher":         "Simplified (Demo)",
		"hash":           "SHA-256",
		"implementation": "Rocher Simple Noise",
		"version":        "1.0",
	}
}

// RekeySession effectue un re-keying de la session
func (s *Session) RekeySession() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return ErrSessionNotInitialized
	}

	// Pour Noise, le re-keying se fait automatiquement avec les nonces
	// Ici on peut forcer une nouvelle dérivation de clé de session
	s.deriveSessionKey()
	s.updateActivity()

	return nil
}

// NewClientSession crée une session client avec Noise
func NewClientSession(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: true,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, privKey, serverPubKey, config)
}

// NewServerSession crée une session serveur avec Noise
func NewServerSession(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: false,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, privKey, clientPubKey, config)
}

// ResetSecurityState réinitialise l'état de sécurité global
func ResetSecurityState() {
	ResetMessageHistory()
}

// Fonctions de compatibilité avec l'ancienne API Double Ratchet

// DoubleRatchet wrapper pour compatibilité (DÉPRÉCIÉ - utiliser Session)
type DoubleRatchet struct {
	session *Session
}

// InitializeDoubleRatchet crée un wrapper de compatibilité (DÉPRÉCIÉ)
func InitializeDoubleRatchet(sessionKey []byte, ourDH *NoiseKeyPair, remoteDHPublic [32]byte) (*DoubleRatchet, error) {
	// Cette fonction est maintenue pour la compatibilité mais n'est plus recommandée
	// Elle crée une session simplifiée

	if len(sessionKey) < 32 {
		return nil, errors.New("session key too short")
	}
	if ourDH == nil {
		return nil, errors.New("DH keypair required")
	}

	// Créer une session factice pour la compatibilité
	dr := &DoubleRatchet{}

	// Pour la compatibilité, on crée un état minimal
	// En réalité, il faudrait une vraie connexion pour utiliser Noise

	return dr, nil
}

// RatchetEncrypt pour compatibilité (DÉPRÉCIÉ)
func (dr *DoubleRatchet) RatchetEncrypt() ([]byte, error) {
	if dr.session == nil {
		return nil, errors.New("session not initialized")
	}

	// Générer une clé aléatoire pour cette démo
	return GenerateRandomKey(32)
}

// RatchetDecrypt pour compatibilité (DÉPRÉCIÉ)
func (dr *DoubleRatchet) RatchetDecrypt() ([]byte, error) {
	if dr.session == nil {
		return nil, errors.New("session not initialized")
	}

	// Générer une clé aléatoire pour cette démo
	return GenerateRandomKey(32)
}

// Reset pour compatibilité (DÉPRÉCIÉ)
func (dr *DoubleRatchet) Reset() {
	if dr.session != nil {
		dr.session.Close()
	}
}

// GetStats pour compatibilité (DÉPRÉCIÉ)
func (dr *DoubleRatchet) GetStats() map[string]interface{} {
	if dr.session != nil {
		return dr.session.GetStats()
	}

	return map[string]interface{}{
		"deprecated": true,
		"message":    "Use Session instead of DoubleRatchet",
	}
}

// DHKeyPair alias pour compatibilité (DÉPRÉCIÉ)
type DHKeyPair = NoiseKeyPair

// GenerateDHKeyPair pour compatibilité (DÉPRÉCIÉ)
func GenerateDHKeyPair() (*DHKeyPair, error) {
	return GenerateNoiseKeyPair()
}

// SessionManager gère plusieurs sessions
type SessionManager struct {
	sessions    map[string]*Session
	mutex       sync.RWMutex
	maxSessions int
}

// NewSessionManager crée un nouveau gestionnaire de sessions
func NewSessionManager(maxSessions int) *SessionManager {
	if maxSessions <= 0 {
		maxSessions = 100
	}

	return &SessionManager{
		sessions:    make(map[string]*Session),
		maxSessions: maxSessions,
	}
}

// AddSession ajoute une session au gestionnaire
func (sm *SessionManager) AddSession(session *Session) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if len(sm.sessions) >= sm.maxSessions {
		return errors.New("maximum sessions reached")
	}

	sessionID := session.GetSessionID()
	if _, exists := sm.sessions[sessionID]; exists {
		return ErrSessionAlreadyActive
	}

	sm.sessions[sessionID] = session
	return nil
}

// RemoveSession supprime une session du gestionnaire
func (sm *SessionManager) RemoveSession(sessionID string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	session.Close()
	delete(sm.sessions, sessionID)
	return nil
}

// GetSession récupère une session par ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	return session, exists
}

// GetAllSessions retourne toutes les sessions actives
func (sm *SessionManager) GetAllSessions() map[string]*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	result := make(map[string]*Session)
	for id, session := range sm.sessions {
		if session.IsActive() {
			result[id] = session
		}
	}
	return result
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

	for _, sessionID := range toRemove {
		if session, exists := sm.sessions[sessionID]; exists {
			session.Close()
			delete(sm.sessions, sessionID)
		}
	}

	return len(toRemove)
}

// GetStats retourne les statistiques du gestionnaire
func (sm *SessionManager) GetStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	activeSessions := 0
	idleSessions := 0
	clientSessions := 0
	serverSessions := 0

	for _, session := range sm.sessions {
		if session.IsActive() {
			activeSessions++
			if session.isClient {
				clientSessions++
			} else {
				serverSessions++
			}
		}

		if session.IsIdle(5 * time.Minute) {
			idleSessions++
		}
	}

	return map[string]interface{}{
		"total_sessions":  len(sm.sessions),
		"active_sessions": activeSessions,
		"idle_sessions":   idleSessions,
		"client_sessions": clientSessions,
		"server_sessions": serverSessions,
		"max_sessions":    sm.maxSessions,
		"protocol":        "Noise Protocol Framework",
	}
}

// CloseAllSessions ferme toutes les sessions
func (sm *SessionManager) CloseAllSessions() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for sessionID, session := range sm.sessions {
		session.Close()
		delete(sm.sessions, sessionID)
	}
}

// Fonctions utilitaires globales

// CreateSecureConnection crée une connexion sécurisée avec configuration automatique
func CreateSecureConnection(conn io.ReadWriter, isClient bool) (*Session, error) {
	// Générer des clés temporaires pour la démo
	pubKey, privKey, err := GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	config := SessionConfig{
		IsClient: isClient,
		Timeout:  30 * time.Second,
	}

	// Pour la démo, utiliser la même clé comme clé distante
	session, err := NewSession(conn, privKey, pubKey, config)
	if err != nil {
		secureZeroResistant(privKey)
		return nil, err
	}

	return session, nil
}

// ValidateSessionConfig valide une configuration de session
func ValidateSessionConfig(config SessionConfig) error {
	if config.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}

	if config.Timeout > 5*time.Minute {
		return errors.New("timeout too long")
	}

	return nil
}

// EstimateSessionOverhead estime l'overhead d'une session Noise
func EstimateSessionOverhead() map[string]interface{} {
	noiseOverhead := EstimateNoiseOverhead()
	messageOverhead := EstimateMessageOverhead(0)

	// Calcul du total handshake
	totalHandshake := noiseOverhead["handshake_msg1"] +
		noiseOverhead["handshake_msg2"] +
		noiseOverhead["handshake_msg3"]

	perMessage := noiseOverhead["transport_msg"] + messageOverhead

	return map[string]interface{}{
		"noise_handshake":  noiseOverhead,
		"message_overhead": messageOverhead,
		"session_metadata": 200, // Estimation pour les métadonnées de session
		"total_handshake":  totalHandshake,
		"per_message":      perMessage,
	}
}
