package communication

import (
	"crypto/ed25519"
	"fmt"
	"io"
)

// Session représente une connexion sécurisée…
type Session struct {
	Conn    io.ReadWriter
	Ratchet *DoubleRatchet
	// … autres champs éventuels
}

// NewClientSessionWithHandshake réalise le handshake côté client et initialise le double ratchet.
func NewClientSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*Session, error) {
	handshakeChan, err := ClientPerformKeyExchange(conn, privKey, serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("client handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("client handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]

	ourDH, err := GenerateDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("client DH key generation error: %w", err)
	}

	if err := sendBytes(conn, ourDH.Public[:]); err != nil {
		return nil, fmt.Errorf("client error sending DH public key: %w", err)
	}

	remoteBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("client error receiving remote DH public key: %w", err)
	}
	if len(remoteBytes) != 32 {
		return nil, fmt.Errorf("invalid remote DH public key size")
	}
	var remotePub [32]byte
	copy(remotePub[:], remoteBytes)

	dr, err := InitializeDoubleRatchet(sessionKey, ourDH, remotePub)
	if err != nil {
		return nil, fmt.Errorf("client error initializing double ratchet: %w", err)
	}
	dr.IsServer = false

	return &Session{Conn: conn, Ratchet: dr}, nil
}

// NewServerSessionWithHandshake réalise le handshake côté serveur et initialise le double ratchet.
func NewServerSessionWithHandshake(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*Session, error) {
	handshakeChan, err := ServerPerformKeyExchange(conn, privKey, clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("server handshake error: %w", err)
	}
	result := <-handshakeChan
	if result.Err != nil {
		return nil, fmt.Errorf("server handshake error: %w", result.Err)
	}
	sessionKey := result.Key[:]

	clientPubBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("server error receiving client DH public key: %w", err)
	}
	if len(clientPubBytes) != 32 {
		return nil, fmt.Errorf("invalid client DH public key size")
	}
	var clientPub [32]byte
	copy(clientPub[:], clientPubBytes)

	ourDH, err := GenerateDHKeyPair()
	if err != nil {
		return nil, fmt.Errorf("server DH key generation error: %w", err)
	}
	if err := sendBytes(conn, ourDH.Public[:]); err != nil {
		return nil, fmt.Errorf("server error sending DH public key: %w", err)
	}

	dr, err := InitializeDoubleRatchet(sessionKey, ourDH, clientPub)
	if err != nil {
		return nil, fmt.Errorf("server error initializing double ratchet: %w", err)
	}
	// CORRECTION: Utiliser les paramètres appropriés selon le rôle
	dr.IsServer = true

	return &Session{Conn: conn, Ratchet: dr}, nil
}

// SendSecureMessage utilise désormais le double ratchet pour le chiffrement
func (s *Session) SendSecureMessage(message string, seq uint64, duration int) error {
	// CORRECTION: Utiliser le double ratchet au lieu du protocole simple
	messageKey, err := s.Ratchet.RatchetEncrypt()
	if err != nil {
		return fmt.Errorf("ratchet encrypt error: %w", err)
	}

	encrypted, err := EncryptAESGCM([]byte(message), messageKey)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}

	// Envoyer le message chiffré directement
	_, err = s.Conn.Write([]byte(encrypted + "\n"))
	return err
}

// ReceiveSecureMessage lit et traite un message chiffré via le double ratchet
func (s *Session) ReceiveSecureMessage() (string, error) {
	// CORRECTION: Utiliser le double ratchet pour le déchiffrement
	messageKey, err := s.Ratchet.RatchetDecrypt()
	if err != nil {
		return "", fmt.Errorf("ratchet decrypt error: %w", err)
	}

	// Lire le message depuis la connexion
	buffer := make([]byte, 4096)
	n, err := s.Conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("read error: %w", err)
	}

	// Déchiffrer avec la clé dérivée du ratchet
	decrypted, err := DecryptAESGCM(string(buffer[:n-1]), messageKey) // -1 pour retirer le \n
	if err != nil {
		return "", fmt.Errorf("decryption error: %w", err)
	}

	return string(decrypted), nil
}

// ResetSecurityState réinitialise l'anti‐rejeu global
func ResetSecurityState() {
	ResetMessageHistory()
}
