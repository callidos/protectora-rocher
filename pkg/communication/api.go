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
// (inchangé) :contentReference[oaicite:8]{index=8}:contentReference[oaicite:9]{index=9}
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
// (inchangé) :contentReference[oaicite:10]{index=10}:contentReference[oaicite:11]{index=11}
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
	// Inversion des chaînes pour le serveur
	dr.SendingChain, dr.ReceivingChain = dr.ReceivingChain, dr.SendingChain
	dr.IsServer = true

	return &Session{Conn: conn, Ratchet: dr}, nil
}

// SendSecureMessage utilise désormais JSON + HMAC (via protocole.SendMessage)
// (modifié) :contentReference[oaicite:12]{index=12}:contentReference[oaicite:13]{index=13}
func (s *Session) SendSecureMessage(message string, seq uint64, duration int) error {
	return SendMessage(s.Conn, message, s.Ratchet.RootKey, seq, duration)
}

// ReceiveSecureMessage lit et traite un message JSON encodé + HMAC
// (modifié) :contentReference[oaicite:14]{index=14}:contentReference[oaicite:15]{index=15}
func (s *Session) ReceiveSecureMessage() (string, error) {
	// ReceiveMessage gère lecture, JSON-unmarshal, HMAC et déchiffrement
	return ReceiveMessage(s.Conn, s.Ratchet.RootKey)
}

// ResetSecurityState réinitialise l’anti‐rejeu global
func ResetSecurityState() {
	ResetMessageHistory()
}
