package communication

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
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

// RateLimiter gère la limitation de débit pour éviter le spam
type RateLimiter struct {
	mu           sync.Mutex
	messages     []time.Time
	maxMessages  int
	windowPeriod time.Duration
}

func NewRateLimiter(maxMessages int, windowPeriod time.Duration) *RateLimiter {
	return &RateLimiter{
		messages:     make([]time.Time, 0),
		maxMessages:  maxMessages,
		windowPeriod: windowPeriod,
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowPeriod)

	// Nettoyer les anciens messages
	validMessages := make([]time.Time, 0)
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

	// Ajouter le nouveau message
	rl.messages = append(rl.messages, now)
	return true
}

// ConnectionHandler gère une connexion sécurisée avec rate limiting
type ConnectionHandler struct {
	reader       io.Reader
	writer       io.Writer
	key          []byte
	username     string
	connected    bool
	mu           sync.RWMutex
	rateLimiter  *RateLimiter
	startTime    time.Time
	messageCount uint64
}

// NewConnectionHandler crée un nouveau gestionnaire de connexion
func NewConnectionHandler(r io.Reader, w io.Writer, sharedKey []byte) *ConnectionHandler {
	return &ConnectionHandler{
		reader:      r,
		writer:      w,
		key:         sharedKey,
		rateLimiter: NewRateLimiter(maxMessagesPerMinute, time.Minute),
		startTime:   time.Now(),
	}
}

// HandleConnection gère le cycle de vie d'une connexion avec timeout configurable
func (ch *ConnectionHandler) HandleConnection() error {
	ch.mu.Lock()
	utils.Logger.Info("Nouvelle connexion établie", map[string]interface{}{
		"start_time": ch.startTime,
	})
	ch.mu.Unlock()

	// Authentification utilisateur avec timeout
	if err := ch.authenticateUser(); err != nil {
		utils.Logger.Warning("Échec d'authentification", map[string]interface{}{
			"error":    "auth_failed",
			"duration": time.Since(ch.startTime),
		})
		ch.sendError(ErrAuthentication)
		return err
	}

	// Envoi du message de bienvenue
	if err := ch.sendWelcome(); err != nil {
		utils.Logger.Error("Échec envoi bienvenue", map[string]interface{}{
			"user": ch.getUsername(),
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
		return nil
	case err := <-errChan:
		return err
	case <-timeout.C:
		return ErrTimeout
	}
}

// validateUsername valide le nom d'utilisateur avec des règles strictes
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
	for _, reserved := range reserved {
		if lowerUsername == reserved {
			return ErrInvalidInput
		}
	}

	return nil
}

// sendWelcome envoie le message de bienvenue
func (ch *ConnectionHandler) sendWelcome() error {
	username := ch.getUsername()
	message := fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", username)
	return SendMessage(ch.writer, message, ch.key, 0, 0)
}

// messageLoop boucle principale de traitement des messages avec rate limiting
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

		// Vérification du rate limiting
		if !ch.rateLimiter.Allow() {
			utils.Logger.Warning("Rate limit exceeded", map[string]interface{}{
				"user": ch.getUsername(),
			})
			ch.sendError(fmt.Errorf("rate limit exceeded"))
			continue
		}

		if line == "FIN_SESSION" {
			utils.Logger.Info("Fin de session demandée", map[string]interface{}{
				"user":     ch.getUsername(),
				"duration": time.Since(ch.startTime),
				"messages": ch.getMessageCount(),
			})
			return ch.closeConnection()
		}

		if err := ch.processMessage(line); err != nil {
			utils.Logger.Error("Erreur traitement message", map[string]interface{}{
				"user": ch.getUsername(),
				"type": "processing_error",
			})
			ch.sendError(ErrProcessing)
		}
	}

	if err := scanner.Err(); err != nil {
		utils.Logger.Error("Erreur lecture scanner", map[string]interface{}{
			"user":  ch.getUsername(),
			"error": err.Error(),
		})
		return ErrConnection
	}

	return nil
}

// processMessage traite un message reçu avec validation
func (ch *ConnectionHandler) processMessage(rawMessage string) error {
	// Validation de la taille avant traitement
	if len(rawMessage) > maxMessageSize {
		return ErrInvalidInput
	}

	// Déchiffrement et validation du message
	message, err := ReceiveMessage(strings.NewReader(rawMessage+"\n"), ch.key)
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
		"total_messages": ch.getMessageCount(),
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

// sendAcknowledgment envoie un accusé de réception
func (ch *ConnectionHandler) sendAcknowledgment() error {
	return SendMessage(ch.writer, "Message reçu avec succès.", ch.key, 0, 0)
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
			"user": ch.getUsername(),
		})
	}
}

// closeConnection ferme proprement la connexion
func (ch *ConnectionHandler) closeConnection() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.connected = false

	utils.Logger.Info("Connexion fermée", map[string]interface{}{
		"user":     ch.username,
		"duration": time.Since(ch.startTime),
		"messages": ch.messageCount,
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
	ch.mu.Lock()
	defer ch.mu.Unlock()
	ch.messageCount++
}

func (ch *ConnectionHandler) getMessageCount() uint64 {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	return ch.messageCount
}

// GetStats retourne les statistiques de la connexion
func (ch *ConnectionHandler) GetStats() map[string]interface{} {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	return map[string]interface{}{
		"username":      ch.username,
		"connected":     ch.connected,
		"start_time":    ch.startTime,
		"duration":      time.Since(ch.startTime),
		"message_count": ch.messageCount,
		"rate_limited":  !ch.rateLimiter.Allow(), // Test sans consommer
	}
}

// SetTimeout configure le timeout de connexion
func (ch *ConnectionHandler) SetTimeout(timeout time.Duration) {
	// Cette méthode pourrait être étendue pour modifier dynamiquement les timeouts
	if timeout > 0 && timeout < 5*time.Minute {
		// Implémentation future pour timeout dynamique
	}
}

// HandleConnection fonction globale pour compatibilité
func HandleConnection(r io.Reader, w io.Writer, sharedKey []byte) {
	handler := NewConnectionHandler(r, w, sharedKey)
	if err := handler.HandleConnection(); err != nil {
		utils.Logger.Error("Connexion terminée avec erreur", map[string]interface{}{
			"duration": time.Since(handler.startTime),
		})
	}
}
