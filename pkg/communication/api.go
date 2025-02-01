package communication

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Session représente une connexion sécurisée dont le protocole gère automatiquement la clé de session et le double ratchet.
type Session struct {
	Conn    io.ReadWriter  // Connexion réseau ou flux de communication.
	Ratchet *DoubleRatchet // État du double ratchet.
}

// NewClientSessionWithHandshake réalise la partie handshake côté client (initiateur) et initialise le double ratchet.
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
	sessionKey := result.Key[:] // Clé de session obtenue par le handshake.
	dr, err := InitializeDoubleRatchet(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize double ratchet: %w", err)
	}
	// Pour le client, on utilise les chaînes telles que dérivées.
	return &Session{
		Conn:    conn,
		Ratchet: dr,
	}, nil
}

// NewServerSessionWithHandshake réalise la partie handshake côté serveur (répondeur) et initialise le double ratchet.
func NewServerSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey) (*Session, error) {
	handshakeChan, err := ServerPerformKeyExchange(conn, privKey)
	if err != nil {
		return nil, fmt.Errorf("server handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("server handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:] // Clé de session obtenue par le handshake.
	dr, err := InitializeDoubleRatchet(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize double ratchet: %w", err)
	}
	// Pour le serveur, on inverse les chaînes : sa chaîne d'envoi correspond à la chaîne de réception du client, et vice-versa.
	dr.SendingChain, dr.ReceivingChain = dr.ReceivingChain, dr.SendingChain
	return &Session{
		Conn:    conn,
		Ratchet: dr,
	}, nil
}

// EncryptMessage chiffre un message en clair en utilisant la chaîne d'envoi du double ratchet.
// La fonction dérive une clé de message, met à jour la chaîne et chiffre le message avec AES-GCM.
func (s *Session) EncryptMessage(message string) (string, error) {
	if s.Ratchet == nil {
		return "", errors.New("double ratchet is not initialized")
	}
	// Obtenir la clé de message à partir de la chaîne d'envoi.
	messageKey, _, err := s.Ratchet.RatchetEncrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet encryption failed: %w", err)
	}
	return EncryptAESGCM([]byte(message), messageKey)
}

// DecryptMessage déchiffre un message encodé en base64 en utilisant la chaîne de réception du double ratchet.
func (s *Session) DecryptMessage(encryptedMessage string) (string, error) {
	if s.Ratchet == nil {
		return "", errors.New("double ratchet is not initialized")
	}
	// Obtenir la clé de message à partir de la chaîne de réception.
	messageKey, _, err := s.Ratchet.RatchetDecrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet decryption failed: %w", err)
	}
	plaintext, err := DecryptAESGCM(encryptedMessage, messageKey)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SendSecureMessage envoie un message sécurisé via la connexion associée à la session.
// Le message est formaté sous la forme : "seqNum|timestamp|duration|ciphertext|hmac"
func (s *Session) SendSecureMessage(message string, seqNum uint64, duration int) error {
	ciphertext, err := s.EncryptMessage(message)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}
	timestamp := time.Now().Unix()
	formatted := fmt.Sprintf("%d|%d|%d|%s", seqNum, timestamp, duration, ciphertext)
	hmacVal := GenerateHMAC(formatted, s.Ratchet.RootKey)
	finalMessage := fmt.Sprintf("%s|%s\n", formatted, hmacVal)
	_, err = s.Conn.Write([]byte(finalMessage))
	return err
}

// ReceiveSecureMessage reçoit un message sécurisé depuis la connexion associée à la session.
// Il attend un message au format : "seqNum|timestamp|duration|ciphertext|hmac", vérifie le HMAC et déchiffre le contenu.
func (s *Session) ReceiveSecureMessage() (string, error) {
	reader := bufio.NewReader(s.Conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, "|", 5)
	if len(parts) != 5 {
		return "", errors.New("invalid message format")
	}
	// Reconstituer le message sans le HMAC et vérifier l'intégrité.
	msgWithoutHMAC := strings.Join(parts[:4], "|")
	expectedHMAC := GenerateHMAC(msgWithoutHMAC, s.Ratchet.RootKey)
	if expectedHMAC != parts[4] {
		return "", errors.New("HMAC verification failed")
	}
	ciphertext := parts[3]
	return s.DecryptMessage(ciphertext)
}

// ResetSecurityState réinitialise l'état global de sécurité (historique des messages et état d'échange de clés).
func ResetSecurityState() {
	ResetMessageHistory()
	ResetKeyExchangeState()
}
