package communication

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
)

// Session représente une connexion sécurisée dont le protocole gère automatiquement la clé de session.
type Session struct {
	Conn io.ReadWriter // Connexion réseau ou flux de communication.
	Key  []byte        // Clé de session établie via le handshake.
}

// NewClientSessionWithHandshake réalise la partie handshake côté client (initiateur).
// Il n'est pas nécessaire de fournir une clé pré-partagée ; la clé de session est dérivée automatiquement.
func NewClientSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey) (*Session, error) {
	handshakeChan, err := ClientPerformKeyExchange(conn, privKey)
	if err != nil {
		return nil, fmt.Errorf("client handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("client handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]
	return &Session{
		Conn: conn,
		Key:  sessionKey,
	}, nil
}

// NewServerSessionWithHandshake réalise la partie handshake côté serveur (répondeur).
func NewServerSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey) (*Session, error) {
	handshakeChan, err := ServerPerformKeyExchange(conn, privKey)
	if err != nil {
		return nil, fmt.Errorf("server handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("server handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]
	return &Session{
		Conn: conn,
		Key:  sessionKey,
	}, nil
}

// EncryptMessage chiffre un message en clair avec la clé de session et retourne le message encodé en base64.
func (s *Session) EncryptMessage(message string) (string, error) {
	if len(s.Key) == 0 {
		return "", errors.New("la clé de session n'est pas initialisée")
	}
	return EncryptAESGCM([]byte(message), s.Key)
}

// DecryptMessage déchiffre un message encodé en base64 avec la clé de session.
func (s *Session) DecryptMessage(encryptedMessage string) (string, error) {
	decrypted, err := DecryptAESGCM(encryptedMessage, s.Key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// SendSecureMessage envoie un message sécurisé via la connexion associée à la session.
func (s *Session) SendSecureMessage(message string, seqNum uint64, duration int) error {
	return SendMessage(s.Conn, message, s.Key, seqNum, duration)
}

// ReceiveSecureMessage reçoit un message sécurisé via la connexion associée à la session.
func (s *Session) ReceiveSecureMessage() (string, error) {
	return ReceiveMessage(s.Conn, s.Key)
}

// ResetSecurityState réinitialise l'état global de sécurité.
func ResetSecurityState() {
	ResetMessageHistory()
	ResetKeyExchangeState()
}
