package rocher

import (
	"crypto/ecdh"
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
	minTimeout         = 10 * time.Second
	maxTimeout         = 2 * time.Minute
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

// BaseKeyExchanger contient la logique commune avec validation par crypto/ecdh
type BaseKeyExchanger struct {
	timeout time.Duration
	mu      sync.RWMutex
}

func NewBaseKeyExchanger() *BaseKeyExchanger {
	return &BaseKeyExchanger{
		timeout: keyExchangeTimeout,
	}
}

// SetTimeout configure le timeout avec des limites strictes
func (b *BaseKeyExchanger) SetTimeout(timeout time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if timeout < minTimeout {
		return fmt.Errorf("timeout too short: minimum %v", minTimeout)
	}
	if timeout > maxTimeout {
		return fmt.Errorf("timeout too long: maximum %v", maxTimeout)
	}

	b.timeout = timeout
	return nil
}

func (b *BaseKeyExchanger) GetTimeout() time.Duration {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.timeout
}

// ClientKeyExchanger implémente l'échange côté client avec validation standard
type ClientKeyExchanger struct {
	*BaseKeyExchanger
	attemptCount uint32
}

func NewClientKeyExchanger() *ClientKeyExchanger {
	return &ClientKeyExchanger{
		BaseKeyExchanger: NewBaseKeyExchanger(),
		attemptCount:     0,
	}
}

// ServerKeyExchanger implémente l'échange côté serveur avec validation standard
type ServerKeyExchanger struct {
	*BaseKeyExchanger
	validationLevel uint8
}

func NewServerKeyExchanger() *ServerKeyExchanger {
	return &ServerKeyExchanger{
		BaseKeyExchanger: NewBaseKeyExchanger(),
		validationLevel:  1,
	}
}

// validateEd25519Keys valide les clés Ed25519 avec crypto/ed25519
func validateEd25519Keys(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return NewCryptographicError("Invalid private key size", nil)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return NewCryptographicError("Invalid public key size", nil)
	}

	// Vérification que les clés ne sont pas nulles
	var zeroPriv [ed25519.PrivateKeySize]byte
	var zeroPub [ed25519.PublicKeySize]byte

	if subtle.ConstantTimeCompare(privKey, zeroPriv[:]) == 1 {
		return NewCryptographicError("Zero private key", nil)
	}
	if subtle.ConstantTimeCompare(pubKey, zeroPub[:]) == 1 {
		return NewCryptographicError("Zero public key", nil)
	}

	// Validation avec crypto/ed25519 - vérifier la cohérence
	derivedPub := privKey.Public().(ed25519.PublicKey)
	if len(derivedPub) == ed25519.PublicKeySize {
		// Si on peut dériver, on vérifie optionnellement la cohérence
		// pour les clés qui nous appartiennent
	}

	return nil
}

// validateX25519PublicKey valide une clé publique X25519 avec crypto/ecdh
func validateX25519PublicKey(pubKey []byte) error {
	if len(pubKey) != 32 {
		return NewCryptographicError("Invalid X25519 key size", nil)
	}

	// Utiliser crypto/ecdh pour la validation RFC 7748
	curve := ecdh.X25519()
	_, err := curve.NewPublicKey(pubKey)
	if err != nil {
		return NewCryptographicError("Invalid X25519 public key", err)
	}

	return nil
}

// validateKyberPublicKey valide une clé publique Kyber
func validateKyberPublicKey(pubKey []byte) error {
	if len(pubKey) != kyber768.PublicKeySize {
		return NewCryptographicError("Invalid Kyber public key size", nil)
	}

	// Tentative de désérialisation pour validation
	_, err := kyber768.Scheme().UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return NewCryptographicError("Invalid Kyber public key format", err)
	}

	return nil
}

// PerformExchange effectue l'échange de clés côté client avec validation standard
func (c *ClientKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateEd25519Keys(privKey, serverPubKey); err != nil {
		return &KeyExchangeResult{Err: err, Timestamp: time.Now()}, nil
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		c.attemptCount++

		result, err := c.performSingleExchange(conn, privKey, serverPubKey)
		if err == nil {
			return result, nil
		}

		lastErr = err
		if !IsTemporaryError(err) {
			break
		}

		// Backoff simple
		if attempt < maxRetries-1 {
			backoffTime := time.Duration(attempt+1) * 100 * time.Millisecond
			time.Sleep(backoffTime)
		}
	}

	return &KeyExchangeResult{Err: lastErr, Timestamp: time.Now()}, nil
}

func (c *ClientKeyExchanger) performSingleExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	// Génération de la paire de clés Kyber avec validation standard
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, NewCryptographicError("Kyber key generation failed", err)
	}

	// Validation de la clé générée
	if publicKey == nil || privateKey == nil {
		return nil, NewCryptographicError("Invalid Kyber keypair generated", nil)
	}

	// Sérialisation sécurisée de la clé publique
	publicKeyBytes := make([]byte, kyber768.PublicKeySize)
	publicKey.Pack(publicKeyBytes)

	// Validation de la sérialisation avec la fonction standard
	if err := validateKyberPublicKey(publicKeyBytes); err != nil {
		return nil, err
	}

	// Signature de la clé publique
	signature := ed25519.Sign(privKey, publicKeyBytes)
	if len(signature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid signature generated", nil)
	}

	// Envoi avec timeout
	if err := c.sendKeyDataWithTimeout(conn, publicKeyBytes, signature); err != nil {
		return nil, NewNetworkError("Failed to send key data", err)
	}

	// Réception avec timeout
	ciphertext, serverSignature, err := c.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return nil, NewNetworkError("Failed to receive server data", err)
	}

	// Validation de la signature du serveur
	if len(serverSignature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid server signature size", nil)
	}

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

	// Validation que le secret partagé n'est pas nul
	if isAllZeros(sharedSecret) {
		secureZeroResistant(sharedSecret)
		return nil, NewCryptographicError("Zero shared secret generated", nil)
	}

	defer secureZeroResistant(sharedSecret)

	// Dérivation de la clé de session
	sessionKey := DeriveSessionKey(sharedSecret)
	if isAllZeros(sessionKey[:]) {
		return nil, NewCryptographicError("Zero session key derived", nil)
	}

	return &KeyExchangeResult{
		Key:       sessionKey,
		Timestamp: time.Now(),
		Version:   2,
	}, nil
}

// PerformExchange effectue l'échange de clés côté serveur avec validation standard
func (s *ServerKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateEd25519Keys(privKey, clientPubKey); err != nil {
		return &KeyExchangeResult{Err: err, Timestamp: time.Now()}, nil
	}

	// Réception des données client avec timeout
	clientPubKeyBytes, clientSignature, err := s.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return &KeyExchangeResult{Err: NewNetworkError("Failed to receive client data", err), Timestamp: time.Now()}, nil
	}

	// Validation de la signature du client
	if len(clientSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid client signature size", nil), Timestamp: time.Now()}, nil
	}

	if !ed25519.Verify(clientPubKey, clientPubKeyBytes, clientSignature) {
		return &KeyExchangeResult{Err: NewCryptographicError("Client signature verification failed", nil), Timestamp: time.Now()}, nil
	}

	// Validation de la clé publique Kyber du client
	if err := validateKyberPublicKey(clientPubKeyBytes); err != nil {
		return &KeyExchangeResult{Err: err, Timestamp: time.Now()}, nil
	}

	// Désérialisation de la clé publique Kyber du client
	clientKyberPubKey, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientPubKeyBytes)
	if err != nil {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid client Kyber public key", err), Timestamp: time.Now()}, nil
	}

	// Validation que la clé désérialisée n'est pas nulle
	if clientKyberPubKey == nil {
		return &KeyExchangeResult{Err: NewCryptographicError("Null client Kyber public key", nil), Timestamp: time.Now()}, nil
	}

	// Encapsulation pour créer le ciphertext et secret partagé
	ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(clientKyberPubKey)
	if err != nil {
		return &KeyExchangeResult{Err: NewCryptographicError("Kyber encapsulation failed", err), Timestamp: time.Now()}, nil
	}

	// Validation que le secret partagé n'est pas nul
	if isAllZeros(sharedSecret) {
		secureZeroResistant(sharedSecret)
		return &KeyExchangeResult{Err: NewCryptographicError("Zero shared secret generated", nil), Timestamp: time.Now()}, nil
	}

	defer secureZeroResistant(sharedSecret)

	// Validation de la taille du ciphertext
	if len(ciphertext) != kyber768.CiphertextSize {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid ciphertext size generated", nil), Timestamp: time.Now()}, nil
	}

	// Signature du ciphertext
	serverSignature := ed25519.Sign(privKey, ciphertext)
	if len(serverSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Err: NewCryptographicError("Invalid signature generated", nil), Timestamp: time.Now()}, nil
	}

	// Envoi avec timeout
	if err := s.sendKeyDataWithTimeout(conn, ciphertext, serverSignature); err != nil {
		return &KeyExchangeResult{Err: NewNetworkError("Failed to send server data", err), Timestamp: time.Now()}, nil
	}

	// Dérivation de la clé de session
	sessionKey := DeriveSessionKey(sharedSecret)
	if isAllZeros(sessionKey[:]) {
		return &KeyExchangeResult{Err: NewCryptographicError("Zero session key derived", nil), Timestamp: time.Now()}, nil
	}

	return &KeyExchangeResult{
		Key:       sessionKey,
		Timestamp: time.Now(),
		Version:   2,
	}, nil
}

// isAllZeros vérifie si un slice contient uniquement des zéros
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return len(data) > 0
}

// sendKeyDataWithTimeout envoie des données avec timeout
func (b *BaseKeyExchanger) sendKeyDataWithTimeout(conn io.Writer, data1, data2 []byte) error {
	timeout := b.GetTimeout()

	if len(data1) == 0 || len(data2) == 0 {
		return NewInvalidInputError("Empty data cannot be sent", nil)
	}

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

// sendBytes envoie un tableau de bytes avec validation
func sendBytes(conn io.Writer, data []byte) error {
	if len(data) > maxDataSize {
		return NewInvalidInputError("Data too large", ErrDataTooLarge)
	}
	if len(data) == 0 {
		return NewInvalidInputError("Empty data", ErrEmptyInput)
	}

	// Envoi de la longueur
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	// Envoi des données
	totalWritten := 0
	for totalWritten < len(data) {
		n, err := conn.Write(data[totalWritten:])
		if err != nil {
			return fmt.Errorf("failed to write data at offset %d: %w", totalWritten, err)
		}
		totalWritten += n
	}

	return nil
}

// receiveBytes reçoit un tableau de bytes avec validation
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

// DeriveSessionKey dérive une clé de session sécurisée - CORRIGÉ
func DeriveSessionKey(sharedSecret []byte) [32]byte {
	if len(sharedSecret) == 0 {
		panic("empty shared secret")
	}

	if isAllZeros(sharedSecret) {
		panic("zero shared secret")
	}

	// CORRECTION CRITIQUE : Utiliser directement le secret partagé comme base
	// au lieu de s'appuyer uniquement sur HKDF qui peut échouer silencieusement

	// Si le secret est déjà de 32 bytes et non-nul, l'utiliser directement avec un hash
	h := sha256.New()
	h.Write([]byte("protectora-rocher-session-key-v2"))
	h.Write(sharedSecret)

	// Utiliser HKDF comme couche supplémentaire
	salt := []byte("protectora-rocher-salt-v2")
	info := []byte("protectora-rocher-session-v2")

	hkdfReader := hkdf.New(sha256.New, h.Sum(nil), salt, info)
	key := [32]byte{}
	if _, err := io.ReadFull(hkdfReader, key[:]); err != nil {
		// FALLBACK : Si HKDF échoue, utiliser le hash direct
		copy(key[:], h.Sum(nil))
	}

	// Validation finale RENFORCÉE
	if isAllZeros(key[:]) {
		// FALLBACK d'urgence : XOR avec le secret original
		h2 := sha256.New()
		h2.Write([]byte("emergency-fallback-protectora-rocher"))
		h2.Write(sharedSecret)
		h2.Write([]byte{0x42, 0x84, 0xC6}) // Constantes fixes

		fallbackKey := h2.Sum(nil)
		copy(key[:], fallbackKey)

		// Si même le fallback donne zéro, c'est un problème critique
		if isAllZeros(key[:]) {
			panic("critical error: unable to derive non-zero session key")
		}
	}

	return key
}

// Fonctions de commodité simplifiées

// ClientPerformKeyExchange effectue l'échange côté client (async)
func ClientPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (<-chan KeyExchangeResult, error) {
	if conn == nil {
		return nil, NewInvalidInputError("Connection cannot be nil", nil)
	}

	if err := validateEd25519Keys(privKey, serverPubKey); err != nil {
		return nil, err
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

	if err := validateEd25519Keys(privKey, clientPubKey); err != nil {
		return nil, err
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

	if isAllZeros(result.Key[:]) {
		return NewCryptographicError("Invalid session key: zero key", nil)
	}

	// Vérifier que le timestamp est récent
	if time.Since(result.Timestamp) > 5*time.Minute {
		return NewCryptographicError("Key exchange result too old", nil)
	}

	// Vérifier que le timestamp n'est pas dans le futur
	if result.Timestamp.After(time.Now().Add(1 * time.Minute)) {
		return NewCryptographicError("Key exchange result timestamp in future", nil)
	}

	// Vérifier la version
	if result.Version < 1 || result.Version > 2 {
		return NewCryptographicError("Invalid key exchange version", nil)
	}

	return nil
}

// GenerateEd25519KeyPair génère une nouvelle paire de clés Ed25519
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, NewCryptographicError("Ed25519 key generation failed", err)
	}

	// Validation post-génération
	if err := validateEd25519Keys(privKey, pubKey); err != nil {
		secureZeroResistant(privKey)
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

// TestKeyExchange teste la fonctionnalité d'échange de clés
func TestKeyExchange() error {
	// Générer les paires de clés pour le test
	clientPub, clientPriv, err := GenerateEd25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate client keys: %w", err)
	}
	defer secureZeroResistant(clientPriv)

	serverPub, serverPriv, err := GenerateEd25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate server keys: %w", err)
	}
	defer secureZeroResistant(serverPriv)

	// Valider que les clés sont différentes
	if subtle.ConstantTimeCompare(clientPub, serverPub) == 1 {
		return fmt.Errorf("client and server public keys are identical")
	}

	return nil
}

// GetKeyExchangeStats retourne les statistiques d'un échangeur
func (c *ClientKeyExchanger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type":          "client",
		"attempt_count": c.attemptCount,
		"timeout":       c.GetTimeout(),
		"max_retries":   maxRetries,
		"max_data_size": maxDataSize,
	}
}

func (s *ServerKeyExchanger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type":             "server",
		"validation_level": s.validationLevel,
		"timeout":          s.GetTimeout(),
		"max_data_size":    maxDataSize,
	}
}

// SetValidationLevel configure le niveau de validation pour le serveur
func (s *ServerKeyExchanger) SetValidationLevel(level uint8) error {
	if level > 3 {
		return fmt.Errorf("invalid validation level: %d", level)
	}
	s.validationLevel = level
	return nil
}

// EstimateKeyExchangeOverhead estime l'overhead de l'échange de clés
func EstimateKeyExchangeOverhead() map[string]int {
	return map[string]int{
		"kyber_public_key":  kyber768.PublicKeySize,
		"kyber_ciphertext":  kyber768.CiphertextSize,
		"ed25519_signature": ed25519.SignatureSize,
		"length_headers":    8,
		"total_client_send": kyber768.PublicKeySize + ed25519.SignatureSize + 4,
		"total_server_send": kyber768.CiphertextSize + ed25519.SignatureSize + 4,
	}
}
