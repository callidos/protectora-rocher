package communication

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/callidos/protectora-rocher/pkg/utils"
)

const (
	bufferSize           = 1024 * 1024
	maxUsernameLength    = 64
	minUsernameLength    = 3
	maxMessageSize       = 10 * 1024 // 10KB pour les messages texte
	connectionTimeout    = 30 * time.Second
	maxMessagesPerMinute = 60 // Rate limiting
	maxConnections       = 100
)

// RateLimiter gère la limitation de débit pour éviter le spam avec thread-safety
type RateLimiter struct {
	mu           sync.Mutex
	messages     []time.Time
	maxMessages  int
	windowPeriod time.Duration
	lastCleanup  int64 // Timestamp atomique pour optimiser le nettoyage
}

func NewRateLimiter(maxMessages int, windowPeriod time.Duration) *RateLimiter {
	return &RateLimiter{
		messages:     make([]time.Time, 0),
		maxMessages:  maxMessages,
		windowPeriod: windowPeriod,
		lastCleanup:  time.Now().Unix(),
	}
}

// Allow vérifie et consomme atomiquement un token de rate limiting
func (rl *RateLimiter) Allow() bool {
	now := time.Now()

	// Optimisation : nettoyage conditionnel pour éviter les locks fréquents
	if atomic.LoadInt64(&rl.lastCleanup) < now.Add(-rl.windowPeriod/2).Unix() {
		rl.cleanupOldMessages(now)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double vérification après acquisition du lock
	cutoff := now.Add(-rl.windowPeriod)
	validMessages := make([]time.Time, 0, len(rl.messages))
	for _, msgTime := range rl.messages {
		if msgTime.After(cutoff) {
			validMessages = append(validMessages, msgTime)
		}
	}
	rl.messages = validMessages

	// Vérifier si on peut ajouter un nouveau message
	if len(rl.messages) >= rl.maxMessages {
		return false
	}

	// Ajouter le nouveau message atomiquement
	rl.messages = append(rl.messages, now)
	return true
}

// cleanupOldMessages nettoie les anciens messages de manière optimisée
func (rl *RateLimiter) cleanupOldMessages(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := now.Add(-rl.windowPeriod)
	validMessages := make([]time.Time, 0, len(rl.messages))

	for _, msgTime := range rl.messages {
		if msgTime.After(cutoff) {
			validMessages = append(validMessages, msgTime)
		}
	}

	rl.messages = validMessages
	atomic.StoreInt64(&rl.lastCleanup, now.Unix())
}

// GetStats retourne les statistiques du rate limiter
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return map[string]interface{}{
		"current_messages": len(rl.messages),
		"max_messages":     rl.maxMessages,
		"window_period":    rl.windowPeriod,
		"last_cleanup":     time.Unix(atomic.LoadInt64(&rl.lastCleanup), 0),
	}
}

// Reset remet à zéro le rate limiter
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.messages = rl.messages[:0] // Réutiliser le slice sous-jacent
	atomic.StoreInt64(&rl.lastCleanup, time.Now().Unix())
}

// ConnectionHandler gère une connexion sécurisée avec rate limiting thread-safe
type ConnectionHandler struct {
	reader       io.Reader
	writer       io.Writer
	key          []byte
	username     string
	connected    bool
	mu           sync.RWMutex
	rateLimiter  *RateLimiter
	startTime    time.Time
	messageCount uint64 // Atomique pour thread-safety
	sessionID    string // Identifiant unique de session pour l'isolation
	lastActivity int64  // Timestamp atomique de la dernière activité
}

// NewConnectionHandler crée un nouveau gestionnaire de connexion avec session unique
func NewConnectionHandler(r io.Reader, w io.Writer, sharedKey []byte) *ConnectionHandler {
	sessionID := generateSessionID()

	return &ConnectionHandler{
		reader:       r,
		writer:       w,
		key:          sharedKey,
		rateLimiter:  NewRateLimiter(maxMessagesPerMinute, time.Minute),
		startTime:    time.Now(),
		sessionID:    sessionID,
		lastActivity: time.Now().Unix(),
	}
}

// generateSessionID génère un identifiant de session unique
func generateSessionID() string {
	// Utiliser un timestamp nano + compteur pour l'unicité
	return fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), atomic.AddInt64(&sessionCounter, 1))
}

var sessionCounter int64 // Compteur atomique global pour les sessions

func init() {
	atomic.StoreInt64(&sessionCounter, 0)
}

// HandleConnection gère le cycle de vie d'une connexion avec timeout configurable
func (ch *ConnectionHandler) HandleConnection() error {
	ch.mu.Lock()
	utils.Logger.Info("Nouvelle connexion établie", map[string]interface{}{
		"start_time": ch.startTime,
		"session_id": ch.sessionID,
	})
	ch.mu.Unlock()

	// Authentification utilisateur avec timeout
	if err := ch.authenticateUser(); err != nil {
		utils.Logger.Warning("Échec d'authentification", map[string]interface{}{
			"error":      "auth_failed",
			"duration":   time.Since(ch.startTime),
			"session_id": ch.sessionID,
		})
		ch.sendError(ErrAuthentication)
		return err
	}

	// Envoi du message de bienvenue
	if err := ch.sendWelcome(); err != nil {
		utils.Logger.Error("Échec envoi bienvenue", map[string]interface{}{
			"user":       ch.getUsername(),
			"session_id": ch.sessionID,
		})
		return err
	}

	// Boucle de traitement des messages
	return ch.messageLoop()
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

// updateActivity met à jour le timestamp de la dernière activité de manière atomique
func (ch *ConnectionHandler) updateActivity() {
	atomic.StoreInt64(&ch.lastActivity, time.Now().Unix())
}

// sendWelcome envoie le message de bienvenue avec session isolée
func (ch *ConnectionHandler) sendWelcome() error {
	username := ch.getUsername()
	message := fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", username)
	return SendMessageWithSession(ch.writer, message, ch.key, 0, 0, ch.sessionID)
}

// messageLoop boucle principale de traitement des messages avec rate limiting thread-safe
func (ch *ConnectionHandler) messageLoop() error {
	// Scanner avec buffer limité pour éviter les attaques mémoire
	limitedReader := io.LimitReader(ch.reader, messageSizeLimit)
	scanner := bufio.NewScanner(limitedReader)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// Mise à jour de l'activité
		ch.updateActivity()

		// Vérification du rate limiting avec protection thread-safe
		if !ch.rateLimiter.Allow() {
			utils.Logger.Warning("Rate limit exceeded", map[string]interface{}{
				"user":       ch.getUsername(),
				"session_id": ch.sessionID,
			})
			ch.sendError(fmt.Errorf("rate limit exceeded"))
			continue
		}

		if line == "FIN_SESSION" {
			utils.Logger.Info("Fin de session demandée", map[string]interface{}{
				"user":       ch.getUsername(),
				"duration":   time.Since(ch.startTime),
				"messages":   atomic.LoadUint64(&ch.messageCount),
				"session_id": ch.sessionID,
			})
			return ch.closeConnection()
		}

		if err := ch.processMessage(line); err != nil {
			utils.Logger.Error("Erreur traitement message", map[string]interface{}{
				"user":       ch.getUsername(),
				"type":       "processing_error",
				"session_id": ch.sessionID,
			})
			ch.sendError(ErrProcessing)
		}
	}

	if err := scanner.Err(); err != nil {
		utils.Logger.Error("Erreur lecture scanner", map[string]interface{}{
			"user":       ch.getUsername(),
			"error":      err.Error(),
			"session_id": ch.sessionID,
		})
		return ErrConnection
	}

	return nil
}

// processMessage traite un message reçu avec validation et isolation de session
func (ch *ConnectionHandler) processMessage(rawMessage string) error {
	// Validation de la taille avant traitement
	if len(rawMessage) > maxMessageSize {
		return ErrInvalidInput
	}

	// Déchiffrement et validation du message avec session isolée
	message, err := ReceiveMessageWithSession(strings.NewReader(rawMessage+"\n"), ch.key, ch.sessionID)
	if err != nil {
		return err
	}

	// Validation de la taille du message déchiffré
	if len(message) > maxMessageSize {
		return ErrInvalidInput
	}

	// Validation du contenu (pas de caractères de contrôle dangereux)
	if !ch.isValidMessageContent(message) {
		return ErrInvalidInput
	}

	ch.incrementMessageCount()

	utils.Logger.Info("Message traité avec succès", map[string]interface{}{
		"user":           ch.getUsername(),
		"size":           len(message),
		"total_messages": atomic.LoadUint64(&ch.messageCount),
		"session_id":     ch.sessionID,
	})

	// Envoi de l'accusé de réception
	return ch.sendAcknowledgment()
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

// sendAcknowledgment envoie un accusé de réception avec session isolée
func (ch *ConnectionHandler) sendAcknowledgment() error {
	return SendMessageWithSession(ch.writer, "Message reçu avec succès.", ch.key, 0, 0, ch.sessionID)
}

// sendError envoie une réponse d'erreur générique sans révéler d'informations sensibles
func (ch *ConnectionHandler) sendError(err error) {
	// Normaliser les messages d'erreur pour éviter la fuite d'information
	var errorMsg string
	switch err {
	case ErrAuthentication:
		errorMsg = "Erreur d'authentification"
	case ErrProcessing:
		errorMsg = "Erreur de traitement"
	case ErrInvalidInput:
		errorMsg = "Entrée invalide"
	default:
		errorMsg = "Erreur interne"
	}

	response := fmt.Sprintf("Erreur: %s\n", errorMsg)
	if _, writeErr := ch.writer.Write([]byte(response)); writeErr != nil {
		utils.Logger.Error("Échec envoi erreur", map[string]interface{}{
			"user":       ch.getUsername(),
			"session_id": ch.sessionID,
		})
	}
}

// closeConnection ferme proprement la connexion avec nettoyage de session
func (ch *ConnectionHandler) closeConnection() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.connected = false

	// Nettoyer l'historique de session isolé
	ResetSessionHistory(ch.sessionID)

	utils.Logger.Info("Connexion fermée", map[string]interface{}{
		"user":       ch.username,
		"duration":   time.Since(ch.startTime),
		"messages":   atomic.LoadUint64(&ch.messageCount),
		"session_id": ch.sessionID,
	})

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
	}

	// Ajouter les stats du rate limiter
	rateLimiterStats := ch.rateLimiter.GetStats()
	stats["rate_limiter"] = rateLimiterStats

	return stats
}

// SetTimeout configure le timeout de connexion (pour extensions futures)
func (ch *ConnectionHandler) SetTimeout(timeout time.Duration) {
	if timeout > 0 && timeout < 5*time.Minute {
		// Implémentation future pour timeout dynamique
		utils.Logger.Info("Timeout configuré", map[string]interface{}{
			"timeout":    timeout,
			"session_id": ch.sessionID,
		})
	}
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
