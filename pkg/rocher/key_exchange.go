package rocher

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	maxDataSize        = 65536
	keyExchangeTimeout = 30 * time.Second
	maxRetries         = 3
)

// KeyExchangeResult contient le résultat sécurisé de l'échange de clés
type KeyExchangeResult struct {
	SharedSecret [32]byte
	Error        error
	Timestamp    time.Time
	Version      int
}

// KeyExchanger interface pour différents types d'échange de clés
type KeyExchanger interface {
	PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) (*KeyExchangeResult, error)
}

// BaseKeyExchanger contient la logique commune
type BaseKeyExchanger struct {
	timeout time.Duration
}

func NewBaseKeyExchanger() *BaseKeyExchanger {
	return &BaseKeyExchanger{
		timeout: keyExchangeTimeout,
	}
}

// ClientKeyExchanger implémente l'échange côté client avec Kyber768 + X25519
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

// ServerKeyExchanger implémente l'échange côté serveur avec Kyber768 + X25519
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

// validateEd25519Keys valide les clés Ed25519
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

	if constantTimeCompare(privKey, zeroPriv[:]) {
		return NewCryptographicError("Zero private key", nil)
	}
	if constantTimeCompare(pubKey, zeroPub[:]) {
		return NewCryptographicError("Zero public key", nil)
	}

	return nil
}

// validateX25519PublicKey valide une clé publique X25519
func validateX25519PublicKey(pubKey []byte) error {
	if len(pubKey) != 32 {
		return NewCryptographicError("Invalid X25519 key size", nil)
	}

	// Vérifier que ce n'est pas une clé nulle ou invalide
	var zero [32]byte
	if constantTimeCompare(pubKey, zero[:]) {
		return NewCryptographicError("Zero X25519 public key", nil)
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

// PerformExchange effectue l'échange de clés côté client avec Kyber768 + X25519
func (c *ClientKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateEd25519Keys(privKey, serverPubKey); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
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

	return &KeyExchangeResult{Error: lastErr, Timestamp: time.Now()}, nil
}

func (c *ClientKeyExchanger) performSingleExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	// 1. Générer clé éphémère X25519
	var x25519Priv, x25519Pub [32]byte
	if _, err := rand.Read(x25519Priv[:]); err != nil {
		return nil, NewCryptographicError("X25519 key generation failed", err)
	}
	curve25519.ScalarBaseMult(&x25519Pub, &x25519Priv)

	// 2. Générer clé Kyber768
	kyberPub, kyberPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, NewCryptographicError("Kyber key generation failed", err)
	}

	kyberPubBytes := make([]byte, kyber768.PublicKeySize)
	kyberPub.Pack(kyberPubBytes)

	// Validation de la clé générée
	if err := validateKyberPublicKey(kyberPubBytes); err != nil {
		return nil, err
	}

	// 3. Créer message client: x25519Pub + kyberPub
	clientMessage := make([]byte, 32+kyber768.PublicKeySize)
	copy(clientMessage[:32], x25519Pub[:])
	copy(clientMessage[32:], kyberPubBytes)

	// 4. Signer le message
	signature := ed25519.Sign(privKey, clientMessage)
	if len(signature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid signature generated", nil)
	}

	// 5. Envoyer message client avec timeout
	if err := c.sendKeyDataWithTimeout(conn, clientMessage, signature); err != nil {
		return nil, NewNetworkError("Failed to send client data", err)
	}

	// 6. Recevoir réponse serveur avec timeout
	serverResponse, serverSignature, err := c.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return nil, NewNetworkError("Failed to receive server data", err)
	}

	// 7. Valider signature serveur
	if len(serverSignature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid server signature size", nil)
	}

	if !ed25519.Verify(serverPubKey, serverResponse, serverSignature) {
		return nil, NewCryptographicError("Server signature verification failed", nil)
	}

	// 8. Extraire données serveur
	if len(serverResponse) < 32+kyber768.CiphertextSize {
		return nil, NewCryptographicError("Invalid server response size", nil)
	}

	serverX25519Pub := serverResponse[:32]
	kyberCiphertext := serverResponse[32:]

	// Valider clé X25519 du serveur
	if err := validateX25519PublicKey(serverX25519Pub); err != nil {
		return nil, err
	}

	// 9. Calculer secret partagé X25519
	var x25519Secret [32]byte
	curve25519.ScalarMult(&x25519Secret, &x25519Priv, (*[32]byte)(serverX25519Pub))

	// Vérifier que le secret n'est pas nul
	if isAllZeros(x25519Secret[:]) {
		return nil, NewCryptographicError("Zero X25519 shared secret", nil)
	}

	// 10. Décapsuler Kyber
	kyberSecret := make([]byte, kyber768.SharedKeySize)
	kyberPriv.DecapsulateTo(kyberSecret, kyberCiphertext)

	if isAllZeros(kyberSecret) {
		secureZeroMemory(kyberSecret)
		return nil, NewCryptographicError("Zero Kyber shared secret", nil)
	}

	defer secureZeroMemory(kyberSecret)
	defer secureZeroMemory(x25519Secret[:])

	// 11. Combiner les secrets partagés
	finalSecret := combineSharedSecrets(x25519Secret[:], kyberSecret)
	if isAllZeros(finalSecret[:]) {
		return nil, NewCryptographicError("Zero combined secret", nil)
	}

	return &KeyExchangeResult{
		SharedSecret: finalSecret,
		Timestamp:    time.Now(),
		Version:      2,
	}, nil
}

// PerformExchange effectue l'échange de clés côté serveur avec Kyber768 + X25519
func (s *ServerKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateEd25519Keys(privKey, clientPubKey); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	// 1. Recevoir message client avec timeout
	clientMessage, clientSignature, err := s.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return &KeyExchangeResult{Error: NewNetworkError("Failed to receive client data", err), Timestamp: time.Now()}, nil
	}

	// 2. Valider signature client
	if len(clientSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client signature size", nil), Timestamp: time.Now()}, nil
	}

	if !ed25519.Verify(clientPubKey, clientMessage, clientSignature) {
		return &KeyExchangeResult{Error: NewCryptographicError("Client signature verification failed", nil), Timestamp: time.Now()}, nil
	}

	// 3. Extraire clés client
	if len(clientMessage) < 32+kyber768.PublicKeySize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client message size", nil), Timestamp: time.Now()}, nil
	}

	clientX25519Pub := clientMessage[:32]
	clientKyberPubBytes := clientMessage[32:]

	// Valider clés client
	if err := validateX25519PublicKey(clientX25519Pub); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	if err := validateKyberPublicKey(clientKyberPubBytes); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	// 4. Désérialiser clé Kyber client
	clientKyberPub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientKyberPubBytes)
	if err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client Kyber public key", err), Timestamp: time.Now()}, nil
	}

	// 5. Générer clé éphémère X25519 serveur
	var serverX25519Priv, serverX25519Pub [32]byte
	if _, err := rand.Read(serverX25519Priv[:]); err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Server X25519 key generation failed", err), Timestamp: time.Now()}, nil
	}
	curve25519.ScalarBaseMult(&serverX25519Pub, &serverX25519Priv)

	// 6. Encapsuler Kyber
	kyberCiphertext, kyberSecret, err := kyber768.Scheme().Encapsulate(clientKyberPub)
	if err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Kyber encapsulation failed", err), Timestamp: time.Now()}, nil
	}

	if isAllZeros(kyberSecret) {
		secureZeroMemory(kyberSecret)
		return &KeyExchangeResult{Error: NewCryptographicError("Zero Kyber shared secret generated", nil), Timestamp: time.Now()}, nil
	}

	defer secureZeroMemory(kyberSecret)

	// 7. Créer réponse serveur: serverX25519Pub + kyberCiphertext
	serverResponse := make([]byte, 32+len(kyberCiphertext))
	copy(serverResponse[:32], serverX25519Pub[:])
	copy(serverResponse[32:], kyberCiphertext)

	// 8. Signer la réponse
	serverSignature := ed25519.Sign(privKey, serverResponse)
	if len(serverSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid signature generated", nil), Timestamp: time.Now()}, nil
	}

	// 9. Envoyer réponse avec timeout
	if err := s.sendKeyDataWithTimeout(conn, serverResponse, serverSignature); err != nil {
		return &KeyExchangeResult{Error: NewNetworkError("Failed to send server data", err), Timestamp: time.Now()}, nil
	}

	// 10. Calculer secret partagé X25519
	var x25519Secret [32]byte
	curve25519.ScalarMult(&x25519Secret, &serverX25519Priv, (*[32]byte)(clientX25519Pub))

	if isAllZeros(x25519Secret[:]) {
		return &KeyExchangeResult{Error: NewCryptographicError("Zero X25519 shared secret", nil), Timestamp: time.Now()}, nil
	}

	defer secureZeroMemory(x25519Secret[:])

	// 11. Combiner les secrets partagés
	finalSecret := combineSharedSecrets(x25519Secret[:], kyberSecret)
	if isAllZeros(finalSecret[:]) {
		return &KeyExchangeResult{Error: NewCryptographicError("Zero combined secret", nil), Timestamp: time.Now()}, nil
	}

	return &KeyExchangeResult{
		SharedSecret: finalSecret,
		Timestamp:    time.Now(),
		Version:      2,
	}, nil
}

// combineSharedSecrets combine de manière sécurisée les secrets X25519 et Kyber
func combineSharedSecrets(x25519Secret, kyberSecret []byte) [32]byte {
	// Utiliser HKDF pour combiner les deux secrets
	salt := []byte("protectora-rocher-hybrid-kdf-v2")
	info := []byte("protectora-rocher-combined-secret-v2")

	// Concaténer les secrets
	combined := make([]byte, 0, len(x25519Secret)+len(kyberSecret))
	combined = append(combined, x25519Secret...)
	combined = append(combined, kyberSecret...)

	// Dériver le secret final avec HKDF
	hkdfReader := hkdf.New(sha256.New, combined, salt, info)

	var finalSecret [32]byte
	if _, err := io.ReadFull(hkdfReader, finalSecret[:]); err != nil {
		// Fallback en cas d'erreur HKDF (très improbable)
		h := sha256.Sum256(append(combined, salt...))
		copy(finalSecret[:], h[:])
	}

	// Nettoyer les données temporaires
	secureZeroMemory(combined)

	return finalSecret
}

// Supprimé - fonction déplacée vers utilities.go

// constantTimeCompare compare deux slices de manière résistante au timing
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// sendKeyDataWithTimeout envoie des données avec timeout
func (b *BaseKeyExchanger) sendKeyDataWithTimeout(conn io.Writer, data1, data2 []byte) error {
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
	case <-time.After(b.timeout):
		return NewTimeoutError("Send operation timed out", nil)
	}
}

// receiveKeyDataWithTimeout reçoit des données avec timeout
func (b *BaseKeyExchanger) receiveKeyDataWithTimeout(conn io.Reader) ([]byte, []byte, error) {
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
	case <-time.After(b.timeout):
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
			resultChan <- KeyExchangeResult{Error: err, Timestamp: time.Now()}
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
			resultChan <- KeyExchangeResult{Error: err, Timestamp: time.Now()}
		} else {
			resultChan <- *result
		}
	}()

	return resultChan, nil
}

// GenerateEd25519KeyPair génère une nouvelle paire de clés Ed25519
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, NewCryptographicError("Ed25519 key generation failed", err)
	}

	// Validation post-génération
	if err := validateEd25519Keys(privKey, pubKey); err != nil {
		secureZeroMemory(privKey)
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

// ValidateKeyExchangeResult valide un résultat d'échange de clés
func ValidateKeyExchangeResult(result *KeyExchangeResult) error {
	if result == nil {
		return NewInvalidInputError("Nil result", nil)
	}

	if result.Error != nil {
		return result.Error
	}

	if isAllZeros(result.SharedSecret[:]) {
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

// GetKeyExchangeStats retourne les statistiques d'un échangeur
func (c *ClientKeyExchanger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type":          "client",
		"attempt_count": c.attemptCount,
		"timeout":       c.timeout,
		"max_retries":   maxRetries,
		"max_data_size": maxDataSize,
		"algorithms":    []string{"X25519", "Kyber768"},
	}
}

func (s *ServerKeyExchanger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"type":             "server",
		"validation_level": s.validationLevel,
		"timeout":          s.timeout,
		"max_data_size":    maxDataSize,
		"algorithms":       []string{"X25519", "Kyber768"},
	}
}

// EstimateKeyExchangeOverhead estime l'overhead de l'échange de clés hybride
func EstimateKeyExchangeOverhead() map[string]int {
	return map[string]int{
		"x25519_public_key": 32,
		"kyber_public_key":  kyber768.PublicKeySize,
		"kyber_ciphertext":  kyber768.CiphertextSize,
		"ed25519_signature": ed25519.SignatureSize,
		"length_headers":    16, // 4 bytes × 4 messages
		"total_client_send": 32 + kyber768.PublicKeySize + ed25519.SignatureSize + 8,
		"total_server_send": 32 + kyber768.CiphertextSize + ed25519.SignatureSize + 8,
		"total_round_trip":  64 + kyber768.PublicKeySize + kyber768.CiphertextSize + 2*ed25519.SignatureSize + 16,
	}
}
