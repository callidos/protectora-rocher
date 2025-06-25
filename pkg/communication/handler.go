package communication

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
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

// RateLimiter simplifié avec golang.org/x/time/rate
type RateLimiter struct {
	limiter   *rate.Limiter
	mu        sync.RWMutex
	startTime time.Time
}

func NewRateLimiter(maxMessages int, windowPeriod time.Duration) *RateLimiter {
	// Calcul du taux : maxMessages par windowPeriod
	r := rate.Every(windowPeriod / time.Duration(maxMessages))

	return &RateLimiter{
		limiter:   rate.NewLimiter(r, maxMessages), // burst = maxMessages
		startTime: time.Now(),
	}
}

// Allow vérifie si une requête peut passer (thread-safe automatiquement)
func (rl *RateLimiter) Allow() bool {
	return rl.limiter.Allow()
}

// AllowN vérifie si N requêtes peuvent passer
func (rl *RateLimiter) AllowN(n int) bool {
	return rl.limiter.AllowN(time.Now(), n)
}

// Reserve réserve une requête et retourne une réservation
func (rl *RateLimiter) Reserve() *rate.Reservation {
	return rl.limiter.Reserve()
}

// SetLimit change le taux de limitation
func (rl *RateLimiter) SetLimit(newRate rate.Limit) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiter.SetLimit(newRate)
}

// SetBurst change la taille du burst
func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.limiter.SetBurst(newBurst)
}

// GetStats retourne les statistiques du rate limiter
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"limit":      float64(rl.limiter.Limit()),
		"burst":      rl.limiter.Burst(),
		"tokens":     rl.limiter.Tokens(), // Tokens disponibles actuellement
		"start_time": rl.startTime,
		"uptime":     time.Since(rl.startTime),
	}
}

// Reset remet à zéro le rate limiter
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Recréer un nouveau limiter avec les mêmes paramètres
	oldLimit := rl.limiter.Limit()
	oldBurst := rl.limiter.Burst()
	rl.limiter = rate.NewLimiter(oldLimit, oldBurst)
	rl.startTime = time.Now()
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
	return fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), atomic.AddInt64(&sessionCounter, 1))
}

var sessionCounter int64 // Compteur atomique global pour les sessions

func init() {
	atomic.StoreInt64(&sessionCounter, 0)
}

// HandleConnection manages the connection lifecycle with configurable timeout
func (ch *ConnectionHandler) HandleConnection() error {
	ch.mu.Lock()
	fmt.Printf("[INFO] New connection established - session_id: %s\n", ch.sessionID)
	ch.mu.Unlock()

	// User authentication with timeout
	if err := ch.authenticateUser(); err != nil {
		fmt.Printf("[WARNING] Authentication failed - session_id: %s, duration: %v\n",
			ch.sessionID, time.Since(ch.startTime))
		ch.sendError(ErrAuthentication)
		return err
	}

	// Send welcome message
	if err := ch.sendWelcome(); err != nil {
		fmt.Printf("[ERROR] Failed to send welcome message - user: %s, session_id: %s, error: %v\n",
			ch.getUsername(), ch.sessionID, err)
		return err
	}

	// Message processing loop
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

// sendWelcome sends the welcome message with session isolation
func (ch *ConnectionHandler) sendWelcome() error {
	username := ch.getUsername()
	message := fmt.Sprintf("Welcome %s to the secure server.", username)
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

		// Rate limiting check with automatic thread-safety
		if !ch.rateLimiter.Allow() {
			fmt.Printf("[WARNING] Rate limit exceeded - user: %s, session_id: %s\n",
				ch.getUsername(), ch.sessionID)
			ch.sendError(NewRateLimitError("rate limit exceeded", nil))
			continue
		}

		if line == "END_SESSION" {
			fmt.Printf("[INFO] Session end requested - user: %s, duration: %v, messages: %d, session_id: %s\n",
				ch.getUsername(), time.Since(ch.startTime), atomic.LoadUint64(&ch.messageCount), ch.sessionID)
			return ch.closeConnection()
		}

		if err := ch.processMessage(line); err != nil {
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

	fmt.Printf("[INFO] Message processed successfully - user: %s, size: %d, total_messages: %d, session_id: %s\n",
		ch.getUsername(), len(message), atomic.LoadUint64(&ch.messageCount), ch.sessionID)

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

// sendAcknowledgment sends an acknowledgment with session isolation
func (ch *ConnectionHandler) sendAcknowledgment() error {
	return SendMessageWithSession(ch.writer, "Message received successfully.", ch.key, 0, 0, ch.sessionID)
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
	case IsErrorCode(err, ErrorCodeRateLimit):
		errorMsg = "Too many requests, please wait"
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

	// Clean up isolated session history
	ResetSessionHistory(ch.sessionID)

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
	}

	// Ajouter les stats du rate limiter (maintenant plus détaillées)
	rateLimiterStats := ch.rateLimiter.GetStats()
	stats["rate_limiter"] = rateLimiterStats

	return stats
}

// ConfigureRateLimiting permet de reconfigurer le rate limiting à chaud
func (ch *ConnectionHandler) ConfigureRateLimiting(messagesPerMinute int, burstSize int) {
	if messagesPerMinute <= 0 || burstSize <= 0 {
		return
	}

	// Calculer le nouveau taux
	newRate := rate.Every(time.Minute / time.Duration(messagesPerMinute))

	// Apply new parameters
	ch.rateLimiter.SetLimit(newRate)
	ch.rateLimiter.SetBurst(burstSize)

	fmt.Printf("[INFO] Rate limiting reconfigured - session_id: %s, messages_per_minute: %d, burst_size: %d, user: %s\n",
		ch.sessionID, messagesPerMinute, burstSize, ch.getUsername())
}

// SetTimeout configures connection timeout (for future extensions)
func (ch *ConnectionHandler) SetTimeout(timeout time.Duration) {
	if timeout > 0 && timeout < 5*time.Minute {
		fmt.Printf("[INFO] Timeout configured - timeout: %v, session_id: %s\n", timeout, ch.sessionID)
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

// WaitForRateLimit attend qu'une requête puisse passer selon le rate limit
func (ch *ConnectionHandler) WaitForRateLimit() error {
	reservation := ch.rateLimiter.Reserve()
	if !reservation.OK() {
		return NewRateLimitError("rate limit reservation failed", nil)
	}

	delay := reservation.Delay()
	if delay > 0 {
		fmt.Printf("[DEBUG] Rate limit delay - delay: %v, session_id: %s, user: %s\n",
			delay, ch.sessionID, ch.getUsername())
		time.Sleep(delay)
	}

	return nil
}

// GetRateLimitStats retourne les statistiques détaillées du rate limiting
func (ch *ConnectionHandler) GetRateLimitStats() map[string]interface{} {
	stats := ch.rateLimiter.GetStats()
	stats["session_id"] = ch.sessionID
	stats["user"] = ch.getUsername()
	return stats
}
