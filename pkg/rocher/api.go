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
	ErrRatchetNotReady       = errors.New("ratchet not ready")
	ErrConnectionClosed      = errors.New("connection closed")
)

// Session représente une connexion sécurisée avec double ratchet
type Session struct {
	conn       io.ReadWriter
	ratchet    *DoubleRatchet
	sessionKey [32]byte
	isClient   bool
	isActive   bool
	mutex      sync.RWMutex
	sessionID  string

	// Compteurs de messages
	sendSeq uint64
	recvSeq uint64
}

// SessionConfig configuration pour une session
type SessionConfig struct {
	IsClient bool
	Timeout  time.Duration
}

// NewSession crée une nouvelle session avec handshake
func NewSession(conn io.ReadWriter, privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, config SessionConfig) (*Session, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Générer un ID de session unique
	sessionID := fmt.Sprintf("session_%d", time.Now().UnixNano())

	session := &Session{
		conn:      conn,
		isClient:  config.IsClient,
		isActive:  false,
		sessionID: sessionID,
	}

	// Effectuer le handshake
	if err := session.performHandshake(privKey, remotePubKey, config.Timeout); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Initialiser le double ratchet
	if err := session.initializeRatchet(); err != nil {
		return nil, fmt.Errorf("ratchet initialization failed: %w", err)
	}

	session.isActive = true
	return session, nil
}

// performHandshake effectue l'échange de clés initial
func (s *Session) performHandshake(privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey, timeout time.Duration) error {
	resultChan := make(chan KeyExchangeResult, 1)
	var err error

	// Lancer l'échange de clés selon le rôle
	if s.isClient {
		var clientChan <-chan KeyExchangeResult
		clientChan, err = ClientPerformKeyExchange(s.conn, privKey, remotePubKey)
		if err != nil {
			return err
		}

		go func() {
			result := <-clientChan
			resultChan <- result
		}()
	} else {
		var serverChan <-chan KeyExchangeResult
		serverChan, err = ServerPerformKeyExchange(s.conn, privKey, remotePubKey)
		if err != nil {
			return err
		}

		go func() {
			result := <-serverChan
			resultChan <- result
		}()
	}

	// Attendre le résultat avec timeout
	select {
	case result := <-resultChan:
		if result.Err != nil {
			return result.Err
		}
		s.sessionKey = result.Key
		return nil
	case <-time.After(timeout):
		return errors.New("handshake timeout")
	}
}

// initializeRatchet initialise le double ratchet après le handshake
func (s *Session) initializeRatchet() error {
	// Générer nos clés DH
	ourDH, err := GenerateDHKeyPair()
	if err != nil {
		return err
	}

	var remoteDH [32]byte

	if s.isClient {
		// Client: envoie sa clé publique DH puis reçoit celle du serveur
		if err := sendBytes(s.conn, ourDH.Public[:]); err != nil {
			return fmt.Errorf("failed to send DH public key: %w", err)
		}

		remoteBytes, err := receiveBytes(s.conn)
		if err != nil {
			return fmt.Errorf("failed to receive server DH key: %w", err)
		}

		if len(remoteBytes) != 32 {
			return errors.New("invalid server DH key size")
		}
		copy(remoteDH[:], remoteBytes)
	} else {
		// Serveur: reçoit la clé du client puis envoie la sienne
		clientBytes, err := receiveBytes(s.conn)
		if err != nil {
			return fmt.Errorf("failed to receive client DH key: %w", err)
		}

		if len(clientBytes) != 32 {
			return errors.New("invalid client DH key size")
		}
		copy(remoteDH[:], clientBytes)

		if err := sendBytes(s.conn, ourDH.Public[:]); err != nil {
			return fmt.Errorf("failed to send DH public key: %w", err)
		}
	}

	// Initialiser le double ratchet
	s.ratchet, err = InitializeDoubleRatchet(s.sessionKey[:], ourDH, remoteDH)
	if err != nil {
		return err
	}

	s.ratchet.isServer = !s.isClient
	return nil
}

// SendMessage envoie un message sécurisé via le double ratchet
func (s *Session) SendMessage(message string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return ErrSessionNotInitialized
	}

	// Générer une clé de message via le ratchet
	messageKey, err := s.ratchet.RatchetEncrypt()
	if err != nil {
		return fmt.Errorf("ratchet encrypt failed: %w", err)
	}

	// Chiffrer le message avec NaCl
	encrypted, err := EncryptNaClBox([]byte(message), messageKey)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Envoyer le message chiffré avec séquence et session
	s.sendSeq++
	return SendMessageWithSession(s.conn, encrypted, s.sessionKey[:], s.sendSeq, 0, s.sessionID)
}

// ReceiveMessage reçoit et déchiffre un message
func (s *Session) ReceiveMessage() (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return "", ErrSessionNotInitialized
	}

	// Recevoir le message chiffré avec session isolée
	encryptedMessage, err := ReceiveMessageWithSession(s.conn, s.sessionKey[:], s.sessionID)
	if err != nil {
		return "", fmt.Errorf("receive failed: %w", err)
	}

	// Générer la clé de message via le ratchet
	messageKey, err := s.ratchet.RatchetDecrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet decrypt failed: %w", err)
	}

	// Déchiffrer le message avec NaCl
	decrypted, err := DecryptNaClBox(encryptedMessage, messageKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	s.recvSeq++
	return string(decrypted), nil
}

// Close ferme la session proprement
func (s *Session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isActive {
		return nil
	}

	s.isActive = false

	// Nettoyage sécurisé
	if s.ratchet != nil {
		s.ratchet.Reset()
	}
	secureZeroResistant(s.sessionKey[:])

	// Nettoyer l'historique de session
	ResetSessionHistory(s.sessionID)

	// Fermer la connexion si possible
	if closer, ok := s.conn.(io.Closer); ok {
		return closer.Close()
	}

	return nil
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
		"is_active":  s.isActive,
		"is_client":  s.isClient,
		"send_count": s.sendSeq,
		"recv_count": s.recvSeq,
		"session_id": s.sessionID,
	}

	if s.ratchet != nil {
		ratchetStats := s.ratchet.GetStats()
		stats["ratchet_send_num"] = ratchetStats["send_msg_num"]
		stats["ratchet_recv_num"] = ratchetStats["recv_msg_num"]
	}

	return stats
}

// NewClientSession crée une session client
func NewClientSession(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*Session, error) {
	config := SessionConfig{
		IsClient: true,
		Timeout:  30 * time.Second,
	}
	return NewSession(conn, privKey, serverPubKey, config)
}

// NewServerSession crée une session serveur
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
