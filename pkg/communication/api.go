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

// Session représente une connexion sécurisée dont le protocole gère automatiquement
// le handshake, l’échange DH initial et l’évolution des clés via le double ratchet.
type Session struct {
	Conn    io.ReadWriter  // Connexion réseau ou flux de communication.
	Ratchet *DoubleRatchet // État du double ratchet.
}

// NewClientSessionWithHandshake réalise le handshake côté client et initialise le double ratchet.
func NewClientSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey) (*Session, error) {
	// 1. Réaliser le handshake Kyber pour obtenir une clé de session initiale.
	handshakeChan, err := ClientPerformKeyExchange(conn, privKey)
	if err != nil {
		return nil, fmt.Errorf("client handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("client handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]

	// 2. Générer notre paire de clés DH (Curve25519).
	ourDH, err := GenerateDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("client DH key generation error: %w", err)
	}

	// 3. Envoyer notre clé publique DH.
	if err := sendBytes(conn, ourDH.Public[:]); err != nil {
		return nil, fmt.Errorf("client error sending DH public key: %w", err)
	}

	// 4. Recevoir la clé publique DH du serveur.
	remoteDHPublicBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("client error receiving remote DH public key: %w", err)
	}
	if len(remoteDHPublicBytes) != 32 {
		return nil, errors.New("client: invalid remote DH public key size")
	}
	var remoteDHPublic [32]byte
	copy(remoteDHPublic[:], remoteDHPublicBytes)

	// 5. Initialiser le double ratchet avec la clé de session et l'échange DH.
	dr, err := InitializeDoubleRatchet(sessionKey, ourDH, remoteDHPublic)
	if err != nil {
		return nil, fmt.Errorf("client error initializing double ratchet: %w", err)
	}
	dr.IsServer = false // Indique que c'est le client.

	return &Session{
		Conn:    conn,
		Ratchet: dr,
	}, nil
}

// NewServerSessionWithHandshake réalise le handshake côté serveur et initialise le double ratchet.
func NewServerSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey) (*Session, error) {
	// 1. Réaliser le handshake Kyber pour obtenir une clé de session initiale.
	handshakeChan, err := ServerPerformKeyExchange(conn, privKey)
	if err != nil {
		return nil, fmt.Errorf("server handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("server handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]

	// 2. Recevoir la clé publique DH du client.
	remoteDHPublicBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("server error receiving remote DH public key: %w", err)
	}
	if len(remoteDHPublicBytes) != 32 {
		return nil, errors.New("server: invalid remote DH public key size")
	}
	var remoteDHPublic [32]byte
	copy(remoteDHPublic[:], remoteDHPublicBytes)

	// 3. Générer notre paire de clés DH.
	ourDH, err := GenerateDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("server DH key generation error: %w", err)
	}

	// 4. Envoyer notre clé publique DH au client.
	if err := sendBytes(conn, ourDH.Public[:]); err != nil {
		return nil, fmt.Errorf("server error sending DH public key: %w", err)
	}

	// 5. Initialiser le double ratchet.
	dr, err := InitializeDoubleRatchet(sessionKey, ourDH, remoteDHPublic)
	if err != nil {
		return nil, fmt.Errorf("server error initializing double ratchet: %w", err)
	}
	// Inverser les chaînes pour aligner les rôles.
	dr.SendingChain, dr.ReceivingChain = dr.ReceivingChain, dr.SendingChain
	dr.IsServer = true // Indique que c'est le serveur.

	return &Session{
		Conn:    conn,
		Ratchet: dr,
	}, nil
}

// EncryptMessage chiffre un message en utilisant la clé dérivée via le double ratchet.
func (s *Session) EncryptMessage(message string) (string, error) {
	if s.Ratchet == nil {
		return "", errors.New("double ratchet is not initialized")
	}
	// Obtenir la clé de message via la chaîne d'envoi.
	messageKey, err := s.Ratchet.RatchetEncrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet encryption failed: %w", err)
	}
	return EncryptAESGCM([]byte(message), messageKey)
}

// DecryptMessage déchiffre un message en utilisant la clé dérivée via le double ratchet.
func (s *Session) DecryptMessage(encryptedMessage string) (string, error) {
	if s.Ratchet == nil {
		return "", errors.New("double ratchet is not initialized")
	}
	// Obtenir la clé de message via la chaîne de réception.
	messageKey, err := s.Ratchet.RatchetDecrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet decryption failed: %w", err)
	}
	plaintext, err := DecryptAESGCM(encryptedMessage, messageKey)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SendSecureMessage envoie un message sécurisé en formatant le message et en ajoutant un HMAC.
func (s *Session) SendSecureMessage(message string, seqNum uint64, duration int) error {
	timestamp := time.Now().Unix()
	ciphertext, err := s.EncryptMessage(message)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}
	ciphertext = strings.TrimSpace(ciphertext)
	formatted := fmt.Sprintf("%d|%d|%d|%s", seqNum, timestamp, duration, ciphertext)
	hmacVal := GenerateHMAC(formatted, s.Ratchet.RootKey)
	finalMessage := fmt.Sprintf("%s|%s\n", formatted, hmacVal)
	// (Optionnel) Log de débogage
	// fmt.Printf("DEBUG SendSecureMessage: %q\n", finalMessage)
	_, err = s.Conn.Write([]byte(finalMessage))
	return err
}

// ReceiveSecureMessage reçoit un message, vérifie le HMAC et déchiffre le ciphertext.
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
	msgWithoutHMAC := strings.Join(parts[:4], "|")
	expectedHMAC := GenerateHMAC(msgWithoutHMAC, s.Ratchet.RootKey)
	// Log de débogage
	// fmt.Printf("DEBUG ReceiveSecureMessage:\n msgWithoutHMAC: %q\n HMAC reçu: %q\n HMAC attendu: %q\n", msgWithoutHMAC, parts[4], expectedHMAC)
	if expectedHMAC != parts[4] {
		return "", errors.New("HMAC verification failed")
	}
	ciphertext := strings.TrimSpace(parts[3])
	return s.DecryptMessage(ciphertext)
}

// ResetSecurityState réinitialise l'état global.
func ResetSecurityState() {
	ResetMessageHistory()
}
