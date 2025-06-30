// messenger.go
package rocher

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrNotConnected     = errors.New("not connected")
	ErrAlreadyConnected = errors.New("already connected")
	ErrConnectionFailed = errors.New("connection failed")
)

// SimpleMessenger combine l'échange de clés Kyber et le chiffrement NaCl
type SimpleMessenger struct {
	// Composants
	keyExchange *KyberKeyExchange
	channel     *SecureChannel

	// État
	isInitiator bool
	isConnected bool
	startTime   time.Time

	// Statistiques
	messagesSent     uint64
	messagesReceived uint64
	bytesSent        uint64
	bytesReceived    uint64

	// Thread safety
	mu sync.RWMutex
}

// NewSimpleMessenger crée un nouveau messenger
func NewSimpleMessenger(isInitiator bool) *SimpleMessenger {
	return &SimpleMessenger{
		keyExchange: NewKyberKeyExchange(),
		isInitiator: isInitiator,
		startTime:   time.Now(),
	}
}

// Connect établit une connexion sécurisée avec échange de clés Kyber
func (sm *SimpleMessenger) Connect(conn io.ReadWriter) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.isConnected {
		return ErrAlreadyConnected
	}

	// Effectuer l'échange de clés Kyber768
	sharedSecret, err := sm.keyExchange.PerformKeyExchange(conn, sm.isInitiator)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	// Créer le canal sécurisé avec le secret partagé ET le rôle
	sm.channel, err = NewSecureChannel(sharedSecret, sm.isInitiator)
	if err != nil {
		// Nettoyer le secret en cas d'erreur
		secureZeroMemory(sharedSecret)
		return fmt.Errorf("secure channel creation failed: %w", err)
	}

	// Nettoyer le secret de la mémoire
	secureZeroMemory(sharedSecret)

	sm.isConnected = true
	return nil
}

// SendMessage envoie un message sécurisé
func (sm *SimpleMessenger) SendMessage(message string, conn io.Writer) error {
	sm.mu.RLock()
	if !sm.isConnected || sm.channel == nil {
		sm.mu.RUnlock()
		return ErrNotConnected
	}

	channel := sm.channel
	sm.mu.RUnlock()

	// Envoyer le message
	messageBytes := []byte(message)
	err := channel.SendMessage(messageBytes, conn)

	if err == nil {
		// Mettre à jour les statistiques
		sm.mu.Lock()
		sm.messagesSent++
		sm.bytesSent += uint64(len(messageBytes))
		sm.mu.Unlock()
	}

	return err
}

// ReceiveMessage reçoit un message sécurisé
func (sm *SimpleMessenger) ReceiveMessage(conn io.Reader) (string, error) {
	sm.mu.RLock()
	if !sm.isConnected || sm.channel == nil {
		sm.mu.RUnlock()
		return "", ErrNotConnected
	}

	channel := sm.channel
	sm.mu.RUnlock()

	// Recevoir le message
	messageBytes, err := channel.ReceiveMessage(conn)
	if err != nil {
		return "", err
	}

	// Mettre à jour les statistiques
	sm.mu.Lock()
	sm.messagesReceived++
	sm.bytesReceived += uint64(len(messageBytes))
	sm.mu.Unlock()

	return string(messageBytes), nil
}

// IsConnected retourne l'état de la connexion
func (sm *SimpleMessenger) IsConnected() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.isConnected
}

// Close ferme la connexion et nettoie les ressources
func (sm *SimpleMessenger) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isConnected {
		return nil
	}

	if sm.channel != nil {
		sm.channel.Close()
		sm.channel = nil
	}

	sm.isConnected = false
	return nil
}

// GetStats retourne les statistiques du messenger
func (sm *SimpleMessenger) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := map[string]interface{}{
		"is_initiator":      sm.isInitiator,
		"is_connected":      sm.isConnected,
		"start_time":        sm.startTime,
		"uptime":            time.Since(sm.startTime),
		"messages_sent":     sm.messagesSent,
		"messages_received": sm.messagesReceived,
		"bytes_sent":        sm.bytesSent,
		"bytes_received":    sm.bytesReceived,
		"algorithms": map[string]string{
			"key_exchange": "Kyber768",
			"encryption":   "NaCl-secretbox",
			"kdf":          "HKDF-SHA256",
		},
	}

	if sm.keyExchange != nil {
		stats["key_exchange_overhead"] = sm.keyExchange.GetKeyExchangeOverhead()
	}

	if sm.channel != nil {
		stats["message_overhead"] = sm.channel.GetOverhead()
	}

	return stats
}

// SendWithTimeout envoie un message avec timeout
func (sm *SimpleMessenger) SendWithTimeout(message string, conn io.Writer, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		done <- sm.SendMessage(message, conn)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errors.New("send timeout")
	}
}

// ReceiveWithTimeout reçoit un message avec timeout
func (sm *SimpleMessenger) ReceiveWithTimeout(conn io.Reader, timeout time.Duration) (string, error) {
	type result struct {
		message string
		err     error
	}

	done := make(chan result, 1)

	go func() {
		msg, err := sm.ReceiveMessage(conn)
		done <- result{message: msg, err: err}
	}()

	select {
	case res := <-done:
		return res.message, res.err
	case <-time.After(timeout):
		return "", errors.New("receive timeout")
	}
}

// CreateSecureConnection fonction utilitaire pour créer une connexion complète
func CreateSecureConnection(conn io.ReadWriter, isInitiator bool) (*SimpleMessenger, error) {
	messenger := NewSimpleMessenger(isInitiator)

	if err := messenger.Connect(conn); err != nil {
		return nil, fmt.Errorf("failed to establish secure connection: %w", err)
	}

	return messenger, nil
}

// SecureChat structure pour un chat simple entre deux parties
type SecureChat struct {
	messenger *SimpleMessenger
	conn      io.ReadWriter
	username  string

	// Canaux pour les messages
	incomingMessages chan string
	outgoingMessages chan string
	errors           chan error

	// Contrôle
	stopChan chan struct{}
	stopped  bool
	mu       sync.RWMutex
}

// NewSecureChat crée un nouveau chat sécurisé
func NewSecureChat(conn io.ReadWriter, isInitiator bool, username string) (*SecureChat, error) {
	messenger, err := CreateSecureConnection(conn, isInitiator)
	if err != nil {
		return nil, err
	}

	chat := &SecureChat{
		messenger:        messenger,
		conn:             conn,
		username:         username,
		incomingMessages: make(chan string, 10),
		outgoingMessages: make(chan string, 10),
		errors:           make(chan error, 10),
		stopChan:         make(chan struct{}),
	}

	// Démarrer les goroutines de gestion des messages
	go chat.receiveLoop()
	go chat.sendLoop()

	return chat, nil
}

// SendMessage envoie un message via le chat
func (sc *SecureChat) SendMessage(message string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if !sc.stopped {
		select {
		case sc.outgoingMessages <- message:
		default:
			sc.errors <- errors.New("outgoing message buffer full")
		}
	}
}

// ReceiveMessage reçoit un message du chat (non-bloquant)
func (sc *SecureChat) ReceiveMessage() (string, bool) {
	select {
	case msg := <-sc.incomingMessages:
		return msg, true
	default:
		return "", false
	}
}

// GetError récupère une erreur du chat (non-bloquant)
func (sc *SecureChat) GetError() (error, bool) {
	select {
	case err := <-sc.errors:
		return err, true
	default:
		return nil, false
	}
}

// receiveLoop boucle de réception des messages
func (sc *SecureChat) receiveLoop() {
	for {
		select {
		case <-sc.stopChan:
			return
		default:
			message, err := sc.messenger.ReceiveWithTimeout(sc.conn, 10*time.Second) // Timeout plus long
			if err != nil {
				// Si c'est un timeout, continuer
				if err.Error() == "receive timeout" {
					continue
				}
				sc.errors <- fmt.Errorf("receive error: %w", err)
				continue
			}

			select {
			case sc.incomingMessages <- message:
			default:
				sc.errors <- errors.New("incoming message buffer full")
			}
		}
	}
}

// sendLoop boucle d'envoi des messages
func (sc *SecureChat) sendLoop() {
	for {
		select {
		case <-sc.stopChan:
			return
		case message := <-sc.outgoingMessages:
			err := sc.messenger.SendWithTimeout(message, sc.conn, 10*time.Second) // Timeout plus long
			if err != nil {
				sc.errors <- fmt.Errorf("send error: %w", err)
			}
		}
	}
}

// Close ferme le chat
func (sc *SecureChat) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.stopped {
		return nil
	}

	sc.stopped = true
	close(sc.stopChan)

	return sc.messenger.Close()
}

// GetStats retourne les statistiques du chat
func (sc *SecureChat) GetStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	stats := sc.messenger.GetStats()
	stats["username"] = sc.username
	stats["incoming_buffer"] = len(sc.incomingMessages)
	stats["outgoing_buffer"] = len(sc.outgoingMessages)
	stats["error_buffer"] = len(sc.errors)
	stats["is_stopped"] = sc.stopped

	return stats
}
