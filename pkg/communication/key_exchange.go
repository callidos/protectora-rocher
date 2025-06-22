package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
)

const (
	maxDataSize        = 65536
	keyExchangeTimeout = 30 * time.Second
	maxRetries         = 3
)

// KeyExchangeResult contient le résultat sécurisé de l'échange de clés
type KeyExchangeResult struct {
	Key       [32]byte
	Err       error
	Timestamp time.Time
	Version   int
}

// KeyExchanger interface pour différents types d'échange de clés
type KeyExchanger interface {
	PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) (*KeyExchangeResult, error)
}

// BaseKeyExchanger contient la logique commune
type BaseKeyExchanger struct {
	timeout time.Duration
	mu      sync.RWMutex
}

func NewBaseKeyExchanger() *BaseKeyExchanger {
	return &BaseKeyExchanger{
		timeout: keyExchangeTimeout,
	}
}

func (b *BaseKeyExchanger) SetTimeout(timeout time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if timeout > 0 && timeout <= 5*time.Minute {
		b.timeout = timeout
	}
}

func (b *BaseKeyExchanger) GetTimeout() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.timeout
}

// ClientKeyExchanger implémente l'échange côté client avec retry
type ClientKeyExchanger struct {
	*BaseKeyExchanger
}

func NewClientKeyExchanger() *ClientKeyExchanger {
	return &ClientKeyExchanger{
		BaseKeyExchanger: NewBaseKeyExchanger(),
	}
}

// ServerKeyExchanger implémente l'échange côté serveur avec validation renforcée
type ServerKeyExchanger struct {
	*BaseKeyExchanger
}

func NewServerKeyExchanger() *ServerKeyExchanger {
	return &ServerKeyExchanger{
		BaseKeyExchanger: NewBaseKeyExchanger(),
	}
}

// PerformExchange effectue l'échange de clés côté client avec retry automatique
func (c *ClientKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateKeys(privKey, serverPubKey); err != nil {
		return &KeyExchangeResult{Err: err, Timestamp: time.Now()}, nil
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		result, err := c.performSingleExchange(conn, privKey, serverPubKey)
		if err == nil {
			return result, nil
		}

		lastErr = err
		if !IsTemporaryError(err) {
			break
		}

		// Backoff exponentiel pour les retry
		if attempt < maxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
		}
	}

	return &KeyExchangeResult{Err: lastErr, Timestamp: time.Now()}, nil
}

func (c *ClientKeyExchanger) performSingleExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	// Génération de la paire de clés Kyber avec validation
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, NewCryptographicError("Kyber key generation failed", err)
	}

	// Sérialisation sécurisée de la clé publique
	publicKeyBytes := make([]byte, kyber768.PublicKeySize)
	publicKey.Pack(publicKeyBytes)

	// Signature de la clé publique
	signature := ed25519.Sign(privKey, publicKeyBytes)

	// Envoi avec timeout
	if err := c.sendKeyDataWithTimeout(conn, publicKeyBytes, signature); err != nil {
		return nil, NewNetworkError("Failed to send key data", err)
	}

	// Réception avec timeout
	ciphertext, serverSignature, err := c.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return nil, NewNetworkError("Failed to receive server data", err)
	}

	// Vérification de la signature du serveur
	if !ed25519.Verify(serverPubKey, ciphertext, serverSignature) {
		return nil, NewCryptographicError("Server signature verification failed", nil)
	}

	// Validation de la taille du ciphertext
	if len(ciphertext) != kyber768.CiphertextSize {
		return nil, NewCryptographicError("Invalid ciphertext size", nil)
	}

	// Décapsulation sécurisée
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	privateKey.DecapsulateTo(sharedSecret, ciphertext)
	defer secureZero(sharedSecret)

	// Dérivation de la clé de session
	sessionKey := DeriveSessionKey(sharedSecret)

	return &KeyExchangeResult{
		Key:       sessionKey,
		Timestamp: time.Now(),
		Version:   2,
	}, nil
}

// PerformExchange effectue l'échange de clés côté serveur avec validation stricte
func (s *ServerKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateKeys(privKey, clientPubKey); err != nil {
		return &KeyExchangeResult{Err: err, Timestamp: time.Now()}, nil
	}

	// Réception des données client avec timeout
	clientPubKeyBytes, clientSignature, err := s.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return &KeyExchangeResult{Err: NewNetworkError("Failed to receive client data", err), Timestamp: time.Now()}, nil
	}

	// Vérification de la signature du client
	if !ed25519.Verify(clientPubKey, clientPubKeyBytes, clientSignature) {
		return &KeyExchangeResult{Err: NewCryptographicError("Client signature verification failed", nil), Timestamp: time.Now()}, nil
	}

	// Validation de la taille de la clé publique
	if len(clientPubKeyBytes) != kyber768.PublicKeySize {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid client public key size", nil), Timestamp: time.Now()}, nil
	}

	// Désérialisation sécurisée de la clé publique Kyber du client
	clientKyberPubKey, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientPubKeyBytes)
	if err != nil {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid client Kyber public key", err), Timestamp: time.Now()}, nil
	}

	// Encapsulation pour créer le ciphertext et secret partagé
	ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(clientKyberPubKey)
	if err != nil {
		return &KeyExchangeResult{Err: NewCryptographicError("Kyber encapsulation failed", err), Timestamp: time.Now()}, nil
	}
	defer secureZero(sharedSecret)

	// Signature du ciphertext
	serverSignature := ed25519.Sign(privKey, ciphertext)

	// Envoi avec timeout
	if err := s.sendKeyDataWithTimeout(conn, ciphertext, serverSignature); err != nil {
		return &KeyExchangeResult{Err: NewNetworkError("Failed to send server data", err), Timestamp: time.Now()}, nil
	}

	// Dérivation de la clé de session
	sessionKey := DeriveSessionKey(sharedSecret)

	return &KeyExchangeResult{
		Key:       sessionKey,
		Timestamp: time.Now(),
		Version:   2,
	}, nil
}

// validateKeys valide les clés Ed25519
func validateKeys(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return NewCryptographicError("Invalid private key size", nil)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return NewCryptographicError("Invalid public key size", nil)
	}

	// Vérification que la clé publique n'est pas l'identité
	var zero [ed25519.PublicKeySize]byte
	if subtle.ConstantTimeCompare(pubKey, zero[:]) == 1 {
		return NewCryptographicError("Invalid public key: zero key", nil)
	}

	return nil
}

// sendKeyDataWithTimeout envoie des données avec timeout
func (b *BaseKeyExchanger) sendKeyDataWithTimeout(conn io.Writer, data1, data2 []byte) error {
	timeout := b.GetTimeout()

	// Canal pour l'opération d'écriture
	done := make(chan error, 1)

	go func() {
		defer close(done)

		if err := sendBytes(conn, data1); err != nil {
			done <- err
			return
		}

		if err := sendBytes(conn, data2); err != nil {
			done <- err
			return
		}

		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return NewTimeoutError("Send operation timed out", nil)
	}
}

// receiveKeyDataWithTimeout reçoit des données avec timeout
func (b *BaseKeyExchanger) receiveKeyDataWithTimeout(conn io.Reader) ([]byte, []byte, error) {
	timeout := b.GetTimeout()

	type result struct {
		data1, data2 []byte
		err          error
	}

	// Canal pour l'opération de lecture
	done := make(chan result, 1)

	go func() {
		defer close(done)

		data1, err := receiveBytes(conn)
		if err != nil {
			done <- result{err: err}
			return
		}

		data2, err := receiveBytes(conn)
		if err != nil {
			done <- result{err: err}
			return
		}

		done <- result{data1: data1, data2: data2}
	}()

	select {
	case res := <-done:
		return res.data1, res.data2, res.err
	case <-time.After(timeout):
		return nil, nil, NewTimeoutError("Receive operation timed out", nil)
	}
}

// sendBytes envoie un tableau de bytes avec validation renforcée
func sendBytes(conn io.Writer, data []byte) error {
	if len(data) > maxDataSize {
		return NewInvalidInputError("Data too large", ErrDataTooLarge)
	}
	if len(data) == 0 {
		return NewInvalidInputError("Empty data", ErrEmptyInput)
	}

	// Envoi de la longueur avec validation
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	// Envoi des données
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// receiveBytes reçoit un tableau de bytes avec validation stricte
func receiveBytes(conn io.Reader) ([]byte, error) {
	// Lecture de la longueur
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)

	// Validation de la longueur
	if length == 0 {
		return nil, NewInvalidInputError("Zero length data", nil)
	}
	if length > maxDataSize {
		return nil, NewInvalidInputError("Data too large", ErrDataTooLarge)
	}

	// Lecture des données
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return buf, nil
}

// DeriveSessionKey dérive une clé de session sécurisée
func DeriveSessionKey(sharedSecret []byte) [32]byte {
	if len(sharedSecret) == 0 {
		panic("empty shared secret")
	}

	// Utilisation d'HKDF avec sel et contexte
	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-session-v2")

	h := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := [32]byte{}
	if _, err := io.ReadFull(h, key[:]); err != nil {
		panic("HKDF failed: " + err.Error())
	}
	return key
}

// Fonctions de commodité avec gestion d'erreur améliorée

// ClientPerformKeyExchange effectue l'échange côté client (async)
func ClientPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (<-chan KeyExchangeResult, error) {
	if conn == nil {
		return nil, NewInvalidInputError("Connection cannot be nil", nil)
	}

	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		exchanger := NewClientKeyExchanger()
		result, err := exchanger.PerformExchange(conn, privKey, serverPubKey)

		if err != nil {
			resultChan <- KeyExchangeResult{Err: err, Timestamp: time.Now()}
		} else {
			resultChan <- *result
		}
	}()

	return resultChan, nil
}

// ServerPerformKeyExchange effectue l'échange côté serveur (async)
func ServerPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (<-chan KeyExchangeResult, error) {
	if conn == nil {
		return nil, NewInvalidInputError("Connection cannot be nil", nil)
	}

	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		exchanger := NewServerKeyExchanger()
		result, err := exchanger.PerformExchange(conn, privKey, clientPubKey)

		if err != nil {
			resultChan <- KeyExchangeResult{Err: err, Timestamp: time.Now()}
		} else {
			resultChan <- *result
		}
	}()

	return resultChan, nil
}

// ValidateKeyExchangeResult valide un résultat d'échange de clés
func ValidateKeyExchangeResult(result *KeyExchangeResult) error {
	if result == nil {
		return NewInvalidInputError("Nil result", nil)
	}

	if result.Err != nil {
		return result.Err
	}

	// Vérifier que la clé n'est pas nulle
	var zero [32]byte
	if result.Key == zero {
		return NewCryptographicError("Invalid session key: zero key", nil)
	}

	// Vérifier que le timestamp est récent
	if time.Since(result.Timestamp) > 5*time.Minute {
		return NewCryptographicError("Key exchange result too old", nil)
	}

	return nil
}

// GenerateEd25519KeyPair génère une nouvelle paire de clés Ed25519
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, NewCryptographicError("Ed25519 key generation failed", err)
	}
	return pubKey, privKey, nil
}
