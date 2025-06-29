package rocher

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

// ProtocolNegotiation for secure protocol version negotiation
type ProtocolNegotiation struct {
	Version         uint16   `json:"version"`
	SupportedKEM    []string `json:"supported_kem"`
	SupportedCipher []string `json:"supported_cipher"`
	SupportedHash   []string `json:"supported_hash"`
	Timestamp       int64    `json:"timestamp"`
	Nonce           []byte   `json:"nonce"`
}

// KeyExchangeResult contains the secure key exchange result
type KeyExchangeResult struct {
	SharedSecret [32]byte
	Error        error
	Timestamp    time.Time
	Version      int
}

// KeyExchanger interface for different key exchange types
type KeyExchanger interface {
	PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, remotePubKey ed25519.PublicKey) (*KeyExchangeResult, error)
}

// BaseKeyExchanger contains common logic
type BaseKeyExchanger struct {
	timeout time.Duration
}

func NewBaseKeyExchanger() *BaseKeyExchanger {
	return &BaseKeyExchanger{
		timeout: keyExchangeTimeout,
	}
}

// ClientKeyExchanger implements client-side exchange with Kyber768 + X25519
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

// ServerKeyExchanger implements server-side exchange with Kyber768 + X25519
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

// ValidateProtocolNegotiation validates protocol negotiation with anti-downgrade
func ValidateProtocolNegotiation(local, remote *ProtocolNegotiation) error {
	if remote.Version < 2 {
		return NewCryptographicError("Protocol downgrade attempt detected", nil)
	}

	now := time.Now().Unix()
	if abs(now-remote.Timestamp) > 300 { // 5 minutes max
		return NewTimeoutError("Protocol negotiation too old", nil)
	}

	if !hasIntersection(local.SupportedKEM, remote.SupportedKEM) {
		return NewCryptographicError("No compatible KEM algorithms", nil)
	}

	return nil
}

// validateEd25519Keys validates Ed25519 keys
func validateEd25519Keys(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return NewCryptographicError("Invalid private key size", nil)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return NewCryptographicError("Invalid public key size", nil)
	}

	var zeroPriv [ed25519.PrivateKeySize]byte
	var zeroPub [ed25519.PublicKeySize]byte

	if subtle.ConstantTimeCompare(privKey, zeroPriv[:]) == 1 {
		return NewCryptographicError("Zero private key", nil)
	}
	if subtle.ConstantTimeCompare(pubKey, zeroPub[:]) == 1 {
		return NewCryptographicError("Zero public key", nil)
	}

	return nil
}

// validateX25519PublicKey validates X25519 public key
func validateX25519PublicKey(pubKey []byte) error {
	if len(pubKey) != 32 {
		return NewCryptographicError("Invalid X25519 key size", nil)
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(pubKey, zero[:]) == 1 {
		return NewCryptographicError("Zero X25519 public key", nil)
	}
	return nil
}

// validateKyberPublicKey validates Kyber public key
func validateKyberPublicKey(pubKey []byte) error {
	if len(pubKey) != kyber768.PublicKeySize {
		return NewCryptographicError("Invalid Kyber public key size", nil)
	}
	_, err := kyber768.Scheme().UnmarshalBinaryPublicKey(pubKey)
	if err != nil {
		return NewCryptographicError("Invalid Kyber public key format", err)
	}
	return nil
}

// PerformExchange performs client-side key exchange with Kyber768 + X25519
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

		if attempt < maxRetries-1 {
			backoffTime := time.Duration(attempt+1) * 100 * time.Millisecond
			time.Sleep(backoffTime)
		}
	}

	return &KeyExchangeResult{Error: lastErr, Timestamp: time.Now()}, nil
}

func (c *ClientKeyExchanger) performSingleExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	// 1. Generate ephemeral X25519 key
	var x25519Priv, x25519Pub [32]byte
	if _, err := rand.Read(x25519Priv[:]); err != nil {
		return nil, NewCryptographicError("X25519 key generation failed", err)
	}
	curve25519.ScalarBaseMult(&x25519Pub, &x25519Priv)

	// 2. Generate Kyber768 key
	kyberPub, kyberPriv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, NewCryptographicError("Kyber key generation failed", err)
	}

	kyberPubBytes := make([]byte, kyber768.PublicKeySize)
	kyberPub.Pack(kyberPubBytes)

	if err := validateKyberPublicKey(kyberPubBytes); err != nil {
		return nil, err
	}

	// 3. Create client message: x25519Pub + kyberPub
	clientMessage := make([]byte, 32+kyber768.PublicKeySize)
	copy(clientMessage[:32], x25519Pub[:])
	copy(clientMessage[32:], kyberPubBytes)

	// 4. Sign the message
	signature := ed25519.Sign(privKey, clientMessage)
	if len(signature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid signature generated", nil)
	}

	// 5. Send client message with timeout
	if err := c.sendKeyDataWithTimeout(conn, clientMessage, signature); err != nil {
		return nil, NewNetworkError("Failed to send client data", err)
	}

	// 6. Receive server response with timeout
	serverResponse, serverSignature, err := c.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return nil, NewNetworkError("Failed to receive server data", err)
	}

	// 7. Validate server signature
	if len(serverSignature) != ed25519.SignatureSize {
		return nil, NewCryptographicError("Invalid server signature size", nil)
	}

	if !ed25519.Verify(serverPubKey, serverResponse, serverSignature) {
		return nil, NewCryptographicError("Server signature verification failed", nil)
	}

	// 8. Extract server data
	if len(serverResponse) < 32+kyber768.CiphertextSize {
		return nil, NewCryptographicError("Invalid server response size", nil)
	}

	serverX25519Pub := serverResponse[:32]
	kyberCiphertext := serverResponse[32:]

	if err := validateX25519PublicKey(serverX25519Pub); err != nil {
		return nil, err
	}

	// 9. Calculate X25519 shared secret
	var x25519Secret [32]byte
	curve25519.ScalarMult(&x25519Secret, &x25519Priv, (*[32]byte)(serverX25519Pub))

	if isAllZeros(x25519Secret[:]) {
		return nil, NewCryptographicError("Zero X25519 shared secret", nil)
	}

	// 10. Decapsulate Kyber
	kyberSecret := make([]byte, kyber768.SharedKeySize)
	kyberPriv.DecapsulateTo(kyberSecret, kyberCiphertext)

	if isAllZeros(kyberSecret) {
		secureZeroMemory(kyberSecret)
		return nil, NewCryptographicError("Zero Kyber shared secret", nil)
	}

	defer secureZeroMemory(kyberSecret)
	defer secureZeroMemory(x25519Secret[:])

	// 11. Combine shared secrets
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

// PerformExchange performs server-side key exchange with Kyber768 + X25519
func (s *ServerKeyExchanger) PerformExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (*KeyExchangeResult, error) {
	if err := validateEd25519Keys(privKey, clientPubKey); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	// 1. Receive client message with timeout
	clientMessage, clientSignature, err := s.receiveKeyDataWithTimeout(conn)
	if err != nil {
		return &KeyExchangeResult{Error: NewNetworkError("Failed to receive client data", err), Timestamp: time.Now()}, nil
	}

	// 2. Validate client signature
	if len(clientSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client signature size", nil), Timestamp: time.Now()}, nil
	}

	if !ed25519.Verify(clientPubKey, clientMessage, clientSignature) {
		return &KeyExchangeResult{Error: NewCryptographicError("Client signature verification failed", nil), Timestamp: time.Now()}, nil
	}

	// 3. Extract client keys
	if len(clientMessage) < 32+kyber768.PublicKeySize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client message size", nil), Timestamp: time.Now()}, nil
	}

	clientX25519Pub := clientMessage[:32]
	clientKyberPubBytes := clientMessage[32:]

	if err := validateX25519PublicKey(clientX25519Pub); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	if err := validateKyberPublicKey(clientKyberPubBytes); err != nil {
		return &KeyExchangeResult{Error: err, Timestamp: time.Now()}, nil
	}

	// 4. Deserialize client Kyber key
	clientKyberPub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientKyberPubBytes)
	if err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid client Kyber public key", err), Timestamp: time.Now()}, nil
	}

	// 5. Generate server ephemeral X25519 key
	var serverX25519Priv, serverX25519Pub [32]byte
	if _, err := rand.Read(serverX25519Priv[:]); err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Server X25519 key generation failed", err), Timestamp: time.Now()}, nil
	}
	curve25519.ScalarBaseMult(&serverX25519Pub, &serverX25519Priv)

	// 6. Encapsulate Kyber
	kyberCiphertext, kyberSecret, err := kyber768.Scheme().Encapsulate(clientKyberPub)
	if err != nil {
		return &KeyExchangeResult{Error: NewCryptographicError("Kyber encapsulation failed", err), Timestamp: time.Now()}, nil
	}

	if isAllZeros(kyberSecret) {
		secureZeroMemory(kyberSecret)
		return &KeyExchangeResult{Error: NewCryptographicError("Zero Kyber shared secret generated", nil), Timestamp: time.Now()}, nil
	}

	defer secureZeroMemory(kyberSecret)

	// 7. Create server response: serverX25519Pub + kyberCiphertext
	serverResponse := make([]byte, 32+len(kyberCiphertext))
	copy(serverResponse[:32], serverX25519Pub[:])
	copy(serverResponse[32:], kyberCiphertext)

	// 8. Sign the response
	serverSignature := ed25519.Sign(privKey, serverResponse)
	if len(serverSignature) != ed25519.SignatureSize {
		return &KeyExchangeResult{Error: NewCryptographicError("Invalid signature generated", nil), Timestamp: time.Now()}, nil
	}

	// 9. Send response with timeout
	if err := s.sendKeyDataWithTimeout(conn, serverResponse, serverSignature); err != nil {
		return &KeyExchangeResult{Error: NewNetworkError("Failed to send server data", err), Timestamp: time.Now()}, nil
	}

	// 10. Calculate X25519 shared secret
	var x25519Secret [32]byte
	curve25519.ScalarMult(&x25519Secret, &serverX25519Priv, (*[32]byte)(clientX25519Pub))

	if isAllZeros(x25519Secret[:]) {
		return &KeyExchangeResult{Error: NewCryptographicError("Zero X25519 shared secret", nil), Timestamp: time.Now()}, nil
	}

	defer secureZeroMemory(x25519Secret[:])

	// 11. Combine shared secrets
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

// combineSharedSecrets securely combines X25519 and Kyber secrets
func combineSharedSecrets(x25519Secret, kyberSecret []byte) [32]byte {
	salt := []byte("protectora-rocher-hybrid-kdf-v2")
	info := []byte("protectora-rocher-combined-secret-v2")

	combined := make([]byte, 0, len(x25519Secret)+len(kyberSecret))
	combined = append(combined, x25519Secret...)
	combined = append(combined, kyberSecret...)

	hkdfReader := hkdf.New(sha256.New, combined, salt, info)

	var finalSecret [32]byte
	if _, err := io.ReadFull(hkdfReader, finalSecret[:]); err != nil {
		h := sha256.Sum256(append(combined, salt...))
		copy(finalSecret[:], h[:])
	}

	secureZeroMemory(combined)
	return finalSecret
}

// sendKeyDataWithTimeout sends data with timeout
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

// receiveKeyDataWithTimeout receives data with timeout
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

// sendBytes sends byte array with validation
func sendBytes(conn io.Writer, data []byte) error {
	if len(data) > maxDataSize {
		return NewInvalidInputError("Data too large", ErrDataTooLarge)
	}
	if len(data) == 0 {
		return NewInvalidInputError("Empty data", ErrEmptyInput)
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

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

// receiveBytes receives byte array with validation
func receiveBytes(conn io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)

	if length == 0 {
		return nil, NewInvalidInputError("Zero length data", nil)
	}
	if length > maxDataSize {
		return nil, NewInvalidInputError("Data too large", ErrDataTooLarge)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return buf, nil
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, NewCryptographicError("Ed25519 key generation failed", err)
	}

	if err := validateEd25519Keys(privKey, pubKey); err != nil {
		secureZeroMemory(privKey)
		return nil, nil, err
	}

	return pubKey, privKey, nil
}

// ValidateKeyExchangeResult validates a key exchange result
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

	if time.Since(result.Timestamp) > 5*time.Minute {
		return NewCryptographicError("Key exchange result too old", nil)
	}

	if result.Timestamp.After(time.Now().Add(1 * time.Minute)) {
		return NewCryptographicError("Key exchange result timestamp in future", nil)
	}

	if result.Version < 1 || result.Version > 2 {
		return NewCryptographicError("Invalid key exchange version", nil)
	}

	return nil
}

// EstimateKeyExchangeOverhead estimates hybrid key exchange overhead
func EstimateKeyExchangeOverhead() map[string]int {
	return map[string]int{
		"x25519_public_key": 32,
		"kyber_public_key":  kyber768.PublicKeySize,
		"kyber_ciphertext":  kyber768.CiphertextSize,
		"ed25519_signature": ed25519.SignatureSize,
		"length_headers":    16,
		"total_client_send": 32 + kyber768.PublicKeySize + ed25519.SignatureSize + 8,
		"total_server_send": 32 + kyber768.CiphertextSize + ed25519.SignatureSize + 8,
		"total_round_trip":  64 + kyber768.PublicKeySize + kyber768.CiphertextSize + 2*ed25519.SignatureSize + 16,
	}
}

// Helper functions
func hasIntersection(a, b []string) bool {
	for _, itemA := range a {
		for _, itemB := range b {
			if itemA == itemB {
				return true
			}
		}
	}
	return false
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
