package rocher

import (
	"bufio"
	"crypto/ed25519"
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
	maxMessageSize    = 10 * 1024 // 10KB pour les messages texte
	connectionTimeout = 30 * time.Second
	maxConnections    = 100
)

// ConnectionHandler gère une connexion sécurisée avec authentification
type ConnectionHandler struct {
	session      *Session
	reader       io.Reader
	writer       io.Writer
	username     string
	connected    bool
	mu           sync.RWMutex
	startTime    time.Time
	messageCount uint64 // Atomique pour thread-safety
	sessionID    string // Identifiant unique de session
	lastActivity int64  // Timestamp atomique de la dernière activité

	// Clés pour l'établissement de session
	localPrivKey ed25519.PrivateKey
	localPubKey  ed25519.PublicKey
	remotePubKey ed25519.PublicKey
}

// NewConnectionHandler crée un nouveau gestionnaire de connexion
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
	fmt.Printf("[INFO] New connection established - session_id: %s, is_client: %t\n", ch.sessionID, isClient)
	ch.mu.Unlock()

	// User authentication with timeout
	if err := ch.authenticateUser(); err != nil {
		fmt.Printf("[WARNING] Authentication failed - session_id: %s, duration: %v\n",
			ch.sessionID, time.Since(ch.startTime))
		ch.sendError(ErrAuthentication)
		return err
	}

	// Establish secure session with key exchange
	if err := ch.establishSecureSession(isClient); err != nil {
		fmt.Printf("[ERROR] Secure session establishment failed - user: %s, session_id: %s, error: %v\n",
			ch.getUsername(), ch.sessionID, err)
		ch.sendError(ErrProcessing)
		return err
	}

	// Send welcome message through secure channel
	if err := ch.sendSecureWelcome(); err != nil {
		fmt.Printf("[ERROR] Failed to send welcome message - user: %s, session_id: %s, error: %v\n",
			ch.getUsername(), ch.sessionID, err)
		return err
	}

	// Message processing loop through secure channel
	return ch.secureMessageLoop()
}

// authenticateUser authentifie l'utilisateur avec validation renforcée
func (ch *ConnectionHandler) authenticateUser() error {
	// Limitation de lecture pour éviter les attaques DoS
	limitedReader := io.LimitReader(ch.reader, maxUsernameLength*2)
	scanner := bufio.NewScanner(limitedReader)

	// Timeout pour l'authentification
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
			if err := ch.validateUsername(username); err != nil {
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

// validateUsername valide le nom d'utilisateur avec des règles strictes et sécurisées
func (ch *ConnectionHandler) validateUsername(username string) error {
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return ErrInvalidInput
	}

	// Validation stricte des caractères autorisés
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return ErrInvalidInput
		}
	}

	// Vérifier que le nom ne commence pas par un chiffre ou caractère spécial
	if len(username) > 0 {
		first := rune(username[0])
		if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
			return ErrInvalidInput
		}
	}

	// Interdire certains noms réservés
	reserved := []string{"admin", "root", "system", "null", "undefined", "anonymous"}
	lowerUsername := strings.ToLower(username)
	for _, reservedName := range reserved {
		if lowerUsername == reservedName {
			return ErrInvalidInput
		}
	}

	return nil
}

// establishSecureSession établit une session sécurisée avec échange de clés
func (ch *ConnectionHandler) establishSecureSession(isClient bool) error {
	// Créer une connexion wrapper pour l'échange de clés
	conn := &connectionWrapper{reader: ch.reader, writer: ch.writer}

	// Établir la session sécurisée
	session, err := EstablishSecureConnection(conn, isClient, ch.localPrivKey, ch.remotePubKey)
	if err != nil {
		return fmt.Errorf("failed to establish secure connection: %w", err)
	}

	ch.session = session
	ch.sessionID = session.GetSessionID()

	fmt.Printf("[INFO] Secure session established - user: %s, session_id: %s, is_client: %t\n",
		ch.getUsername(), ch.sessionID, isClient)

	return nil
}

// sendSecureWelcome envoie un message de bienvenue via le canal sécurisé
func (ch *ConnectionHandler) sendSecureWelcome() error {
	username := ch.getUsername()
	message := fmt.Sprintf("Welcome %s to the secure server. Session established with quantum-resistant cryptography.", username)

	return ch.session.SendMessage([]byte(message))
}

// secureMessageLoop boucle principale de traitement des messages via canal sécurisé
func (ch *ConnectionHandler) secureMessageLoop() error {
	// Scanner avec buffer limité pour éviter les attaques mémoire
	limitedReader := io.LimitReader(ch.reader, maxMessageSize*2)
	scanner := bufio.NewScanner(limitedReader)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// Mise à jour de l'activité
		ch.updateActivity()

		if line == "END_SESSION" {
			fmt.Printf("[INFO] Session end requested - user: %s, duration: %v, messages: %d, session_id: %s\n",
				ch.getUsername(), time.Since(ch.startTime), atomic.LoadUint64(&ch.messageCount), ch.sessionID)
			return ch.closeConnection()
		}

		if err := ch.processSecureMessage(line); err != nil {
			fmt.Printf("[ERROR] Message processing error - user: %s, session_id: %s, error: %v\n",
				ch.getUsername(), ch.sessionID, err)
			ch.sendError(ErrProcessing)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[ERROR] Scanner read error - user: %s, session_id: %s, error: %v\n",
			ch.getUsername(), ch.sessionID, err)
		return ErrConnection
	}

	return nil
}

// processSecureMessage traite un message reçu via le canal sécurisé
func (ch *ConnectionHandler) processSecureMessage(rawMessage string) error {
	// Validation de la taille avant traitement
	if len(rawMessage) > maxMessageSize {
		return ErrInvalidInput
	}

	// Validation du contenu (pas de caractères de contrôle dangereux)
	if !ch.isValidMessageContent(rawMessage) {
		return ErrInvalidInput
	}

	// Le message arrive déjà en clair via stdin/plaintext
	// Dans un vrai système, les messages arriveraient déjà chiffrés
	// Ici on simule en envoyant le message via le canal sécurisé pour démonstration

	ch.incrementMessageCount()

	fmt.Printf("[INFO] Message processed successfully - user: %s, size: %d, total_messages: %d, session_id: %s\n",
		ch.getUsername(), len(rawMessage), atomic.LoadUint64(&ch.messageCount), ch.sessionID)

	// Envoyer l'accusé de réception via canal sécurisé
	return ch.sendSecureAcknowledgment(rawMessage)
}

// isValidMessageContent valide le contenu du message
func (ch *ConnectionHandler) isValidMessageContent(message string) bool {
	// Vérifier qu'il n'y a pas de caractères de contrôle dangereux
	for _, r := range message {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// sendSecureAcknowledgment envoie un accusé de réception via le canal sécurisé
func (ch *ConnectionHandler) sendSecureAcknowledgment(originalMessage string) error {
	ackMessage := fmt.Sprintf("Message received and processed securely: '%s'", originalMessage)
	return ch.session.SendMessage([]byte(ackMessage))
}

// updateActivity met à jour le timestamp de la dernière activité de manière atomique
func (ch *ConnectionHandler) updateActivity() {
	atomic.StoreInt64(&ch.lastActivity, time.Now().Unix())
}

// sendError sends a generic error response without revealing sensitive information
func (ch *ConnectionHandler) sendError(err error) {
	// Normalize error messages to avoid information leakage
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
		// Check standard errors
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
	if _, writeErr := ch.writer.Write([]byte(response)); writeErr != nil {
		fmt.Printf("[ERROR] Failed to send error response - user: %s, session_id: %s, error: %v\n",
			ch.getUsername(), ch.sessionID, writeErr)
	}
}

// closeConnection properly closes the connection with session cleanup
func (ch *ConnectionHandler) closeConnection() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.connected = false

	// Fermer la session sécurisée
	if ch.session != nil {
		ch.session.Close()
	}

	fmt.Printf("[INFO] Connection closed - user: %s, duration: %v, messages: %d, session_id: %s\n",
		ch.username, time.Since(ch.startTime), atomic.LoadUint64(&ch.messageCount), ch.sessionID)

	if closer, ok := ch.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Méthodes thread-safe pour accéder aux champs

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

// GetStats retourne les statistiques de la connexion
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

	// Ajouter les stats de la session si disponible
	if ch.session != nil {
		sessionStats := ch.session.GetStats()
		stats["session"] = sessionStats
	}

	return stats
}

// IsIdle vérifie si la connexion est inactive depuis trop longtemps
func (ch *ConnectionHandler) IsIdle(maxIdleTime time.Duration) bool {
	lastActivity := atomic.LoadInt64(&ch.lastActivity)
	return time.Since(time.Unix(lastActivity, 0)) > maxIdleTime
}

// GetSessionID retourne l'identifiant de session
func (ch *ConnectionHandler) GetSessionID() string {
	return ch.sessionID
}

// GetSession retourne la session sécurisée
func (ch *ConnectionHandler) GetSession() *Session {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.session
}

// SendSecureMessage envoie un message via le canal sécurisé
func (ch *ConnectionHandler) SendSecureMessage(message string) error {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if ch.session == nil {
		return errors.New("secure session not established")
	}

	return ch.session.SendMessage([]byte(message))
}

// ReceiveSecureMessage reçoit un message via le canal sécurisé
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

// connectionWrapper adapte io.Reader et io.Writer vers io.ReadWriter
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

// ConnectionManager gère plusieurs connexions simultanées
type ConnectionManager struct {
	connections    map[string]*ConnectionHandler
	maxConnections int
	mu             sync.RWMutex
	stats          ConnectionManagerStats
}

// ConnectionManagerStats statistiques du gestionnaire de connexions
type ConnectionManagerStats struct {
	TotalConnections  uint64
	ActiveConnections int
	TotalClosed       uint64
	LastCleanup       time.Time
}

// NewConnectionManager crée un nouveau gestionnaire de connexions
func NewConnectionManager(maxConnections int) *ConnectionManager {
	if maxConnections <= 0 {
		maxConnections = maxConnections
	}

	return &ConnectionManager{
		connections:    make(map[string]*ConnectionHandler),
		maxConnections: maxConnections,
		stats: ConnectionManagerStats{
			LastCleanup: time.Now(),
		},
	}
}

// AddConnection ajoute une connexion au gestionnaire
func (cm *ConnectionManager) AddConnection(handler *ConnectionHandler) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if len(cm.connections) >= cm.maxConnections {
		return fmt.Errorf("maximum connections reached (%d)", cm.maxConnections)
	}

	sessionID := handler.GetSessionID()
	cm.connections[sessionID] = handler
	cm.stats.TotalConnections++
	cm.stats.ActiveConnections = len(cm.connections)

	return nil
}

// RemoveConnection supprime une connexion du gestionnaire
func (cm *ConnectionManager) RemoveConnection(sessionID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	handler, exists := cm.connections[sessionID]
	if !exists {
		return fmt.Errorf("connection not found: %s", sessionID)
	}

	handler.closeConnection()
	delete(cm.connections, sessionID)
	cm.stats.TotalClosed++
	cm.stats.ActiveConnections = len(cm.connections)

	return nil
}

// GetConnection récupère une connexion par ID de session
func (cm *ConnectionManager) GetConnection(sessionID string) (*ConnectionHandler, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	handler, exists := cm.connections[sessionID]
	if !exists {
		return nil, fmt.Errorf("connection not found: %s", sessionID)
	}

	return handler, nil
}

// ListConnections retourne la liste des IDs de sessions actives
func (cm *ConnectionManager) ListConnections() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	sessionIDs := make([]string, 0, len(cm.connections))
	for sessionID, handler := range cm.connections {
		if handler.IsConnected() {
			sessionIDs = append(sessionIDs, sessionID)
		}
	}

	return sessionIDs
}

// CleanupIdleConnections nettoie les connexions inactives
func (cm *ConnectionManager) CleanupIdleConnections(maxIdleTime time.Duration) int {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var toRemove []string

	for sessionID, handler := range cm.connections {
		if !handler.IsConnected() || handler.IsIdle(maxIdleTime) {
			toRemove = append(toRemove, sessionID)
		}
	}

	// Supprimer les connexions inactives
	for _, sessionID := range toRemove {
		if handler, exists := cm.connections[sessionID]; exists {
			handler.closeConnection()
			delete(cm.connections, sessionID)
			cm.stats.TotalClosed++
		}
	}

	cm.stats.ActiveConnections = len(cm.connections)
	cm.stats.LastCleanup = time.Now()

	return len(toRemove)
}

// CloseAllConnections ferme toutes les connexions
func (cm *ConnectionManager) CloseAllConnections() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for sessionID, handler := range cm.connections {
		handler.closeConnection()
		delete(cm.connections, sessionID)
		cm.stats.TotalClosed++
	}

	cm.stats.ActiveConnections = 0
}

// GetStats retourne les statistiques du gestionnaire
func (cm *ConnectionManager) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	activeCount := 0
	connectedCount := 0
	totalMessages := uint64(0)

	for _, handler := range cm.connections {
		if handler.IsConnected() {
			connectedCount++
			activeCount++
			totalMessages += handler.getMessageCount()
		}
	}

	return map[string]interface{}{
		"total_connections":   len(cm.connections),
		"active_connections":  activeCount,
		"connected_count":     connectedCount,
		"max_connections":     cm.maxConnections,
		"total_created":       cm.stats.TotalConnections,
		"total_closed":        cm.stats.TotalClosed,
		"total_messages":      totalMessages,
		"last_cleanup":        cm.stats.LastCleanup,
		"security_algorithms": []string{"Kyber768", "X25519", "Ed25519", "NaCl-secretbox"},
	}
}

// BroadcastMessage diffuse un message à toutes les connexions actives
func (cm *ConnectionManager) BroadcastMessage(message string) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var errors []string
	successCount := 0

	for sessionID, handler := range cm.connections {
		if handler.IsConnected() && handler.GetSession() != nil {
			if err := handler.SendSecureMessage(message); err != nil {
				errors = append(errors, fmt.Sprintf("session %s: %v", sessionID, err))
			} else {
				successCount++
			}
		}
	}

	fmt.Printf("[INFO] Broadcast completed - success: %d, errors: %d\n", successCount, len(errors))

	if len(errors) > 0 {
		return fmt.Errorf("broadcast errors: %v", errors)
	}

	return nil
}

// GetConnectionsByUsername trouve les connexions par nom d'utilisateur
func (cm *ConnectionManager) GetConnectionsByUsername(username string) []*ConnectionHandler {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var connections []*ConnectionHandler
	for _, handler := range cm.connections {
		if handler.GetUsername() == username && handler.IsConnected() {
			connections = append(connections, handler)
		}
	}

	return connections
}

// GetDetailedStats retourne les statistiques détaillées de toutes les connexions
func (cm *ConnectionManager) GetDetailedStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	connectionsStats := make(map[string]interface{})
	for sessionID, handler := range cm.connections {
		connectionsStats[sessionID] = handler.GetStats()
	}

	generalStats := cm.GetStats()
	generalStats["connections_detail"] = connectionsStats

	return generalStats
}

// Fonctions utilitaires globales

// CreateConnectionHandler crée un gestionnaire de connexion avec clés
func CreateConnectionHandler(r io.Reader, w io.Writer, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) *ConnectionHandler {
	return NewConnectionHandler(r, w, localPrivKey, remotePubKey)
}

// HandleSecureConnection gère une connexion sécurisée complète
func HandleSecureConnection(r io.Reader, w io.Writer, localPrivKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, isClient bool) error {
	handler := NewConnectionHandler(r, w, localPrivKey, remotePubKey)
	return handler.HandleConnection(isClient)
}

// ValidateConnectionHandler valide l'état d'un gestionnaire de connexion
func ValidateConnectionHandler(handler *ConnectionHandler) error {
	if handler == nil {
		return errors.New("connection handler is nil")
	}

	if !handler.IsConnected() {
		return errors.New("connection not established")
	}

	if handler.GetSession() == nil {
		return errors.New("secure session not established")
	}

	// Vérifier la santé de la session
	if err := handler.GetSession().SessionHealthCheck(); err != nil {
		return fmt.Errorf("session health check failed: %w", err)
	}

	return nil
}

// EstimateConnectionOverhead estime l'overhead d'une connexion
func EstimateConnectionOverhead() map[string]interface{} {
	sessionOverhead := EstimateSessionOverhead()

	// Extraire les valeurs avec vérification d'existence (map[string]interface{})
	establishment := 1000 // Valeur par défaut
	if val, ok := sessionOverhead["establishment"]; ok {
		if intVal, ok := val.(int); ok {
			establishment = intVal
		}
	}

	perMessage := 100 // Valeur par défaut
	if val, ok := sessionOverhead["per_message"]; ok {
		if intVal, ok := val.(int); ok {
			perMessage = intVal
		}
	}

	return map[string]interface{}{
		"session":             sessionOverhead,
		"authentication":      100, // Username + validation
		"connection_metadata": 150, // Connection handler metadata
		"total_establishment": establishment + 250,
		"per_message":         perMessage,
	}
}

// ConnectionHealthCheck vérifie la santé d'une connexion
func (ch *ConnectionHandler) ConnectionHealthCheck() error {
	if !ch.IsConnected() {
		return errors.New("connection not active")
	}

	if ch.session == nil {
		return errors.New("secure session not established")
	}

	// Vérifier la session
	if err := ch.session.SessionHealthCheck(); err != nil {
		return fmt.Errorf("session health check failed: %w", err)
	}

	// Vérifier l'activité récente
	if ch.IsIdle(30 * time.Minute) {
		return errors.New("connection idle for too long")
	}

	return nil
}

// PingConnection effectue un ping sur la connexion
func (ch *ConnectionHandler) PingConnection(timeout time.Duration) error {
	if ch.session == nil {
		return errors.New("secure session not established")
	}

	return ch.session.SessionPingPong(timeout)
}

// Global connection manager instance
var defaultConnectionManager *ConnectionManager
var connectionManagerOnce sync.Once

// GetDefaultConnectionManager retourne l'instance globale du gestionnaire de connexions
func GetDefaultConnectionManager() *ConnectionManager {
	connectionManagerOnce.Do(func() {
		defaultConnectionManager = NewConnectionManager(maxConnections)
	})
	return defaultConnectionManager
}

// RegisterConnection enregistre une connexion dans le gestionnaire global
func RegisterConnection(handler *ConnectionHandler) error {
	cm := GetDefaultConnectionManager()
	return cm.AddConnection(handler)
}

// UnregisterConnection désenregistre une connexion du gestionnaire global
func UnregisterConnection(sessionID string) error {
	cm := GetDefaultConnectionManager()
	return cm.RemoveConnection(sessionID)
}

// StartConnectionCleanup démarre le nettoyage automatique des connexions inactives
func StartConnectionCleanup(interval time.Duration, maxIdleTime time.Duration) {
	cm := GetDefaultConnectionManager()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			cleaned := cm.CleanupIdleConnections(maxIdleTime)
			if cleaned > 0 {
				fmt.Printf("[INFO] Cleaned up %d idle connections\n", cleaned)
			}
		}
	}()
}

// GetGlobalConnectionStats retourne les statistiques globales des connexions
func GetGlobalConnectionStats() map[string]interface{} {
	cm := GetDefaultConnectionManager()
	return cm.GetStats()
}
