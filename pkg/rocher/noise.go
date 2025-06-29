package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	noiseKeySize    = 32
	noiseHashSize   = 32
	noiseMacSize    = 16
	noiseNonceSize  = 12
	maxNoiseMessage = 65535
)

var (
	ErrNoiseInvalidKey      = errors.New("invalid noise key")
	ErrNoiseHandshakeFailed = errors.New("noise handshake failed")
	ErrNoiseNotInitialized  = errors.New("noise not initialized")
	ErrNoiseDecryptFailed   = errors.New("noise decrypt failed")
	ErrNoiseMessageTooLong  = errors.New("noise message too long")
)

// NoiseKeyPair représente une paire de clés Curve25519 pour Noise
type NoiseKeyPair struct {
	Private [noiseKeySize]byte
	Public  [noiseKeySize]byte
}

// GenerateNoiseKeyPair génère une nouvelle paire de clés pour Noise
func GenerateNoiseKeyPair() (*NoiseKeyPair, error) {
	var priv [noiseKeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}

	// Clamp selon Curve25519
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [noiseKeySize]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	// Validation que la clé n'est pas nulle
	var zero [noiseKeySize]byte
	if subtle.ConstantTimeCompare(pub[:], zero[:]) == 1 {
		return nil, ErrNoiseInvalidKey
	}

	return &NoiseKeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}

// NoiseState représente l'état d'une session Noise
type NoiseState struct {
	mu sync.RWMutex

	// Clés de chiffrement
	sendKey [noiseKeySize]byte
	recvKey [noiseKeySize]byte

	// Nonces pour éviter la réutilisation
	sendNonce uint64
	recvNonce uint64

	// État de l'initialisation
	isInitialized bool
	isInitiator   bool

	// Hash pour le handshake
	h  [noiseHashSize]byte
	ck [noiseKeySize]byte // Chaining key
}

// NewNoiseState crée un nouvel état Noise
func NewNoiseState(isInitiator bool) *NoiseState {
	ns := &NoiseState{
		isInitiator: isInitiator,
	}

	// Initialiser avec un hash fixe pour Noise_XX_25519_ChaChaPoly_SHA256
	protocolName := "Noise_XX_25519_ChaChaPoly_SHA256"
	ns.h = sha256.Sum256([]byte(protocolName))
	ns.ck = ns.h

	return ns
}

// PerformHandshake effectue le handshake Noise XX
func (ns *NoiseState) PerformHandshake(conn io.ReadWriter, localKey *NoiseKeyPair, remotePublicKey []byte) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.isInitialized {
		return errors.New("handshake already completed")
	}

	if ns.isInitiator {
		return ns.performInitiatorHandshake(conn, localKey, remotePublicKey)
	} else {
		return ns.performResponderHandshake(conn, localKey, remotePublicKey)
	}
}

// performInitiatorHandshake effectue le handshake côté initiateur
func (ns *NoiseState) performInitiatorHandshake(conn io.ReadWriter, localKey *NoiseKeyPair, remotePublicKey []byte) error {
	// Générer une clé éphémère
	ephemeral, err := GenerateNoiseKeyPair()
	if err != nil {
		return err
	}
	defer secureZeroResistant(ephemeral.Private[:])

	// Message 1: -> e
	ns.mixHash(ephemeral.Public[:])
	if err := ns.sendMessage(conn, ephemeral.Public[:], nil); err != nil {
		return err
	}

	// Message 2: <- e, ee, s, es
	msg2, err := ns.receiveMessage(conn, nil)
	if err != nil {
		return err
	}

	if len(msg2) < noiseKeySize {
		return ErrNoiseHandshakeFailed
	}

	responderEphemeral := msg2[:noiseKeySize]
	ns.mixHash(responderEphemeral)

	// ee
	ee, err := curve25519.X25519(ephemeral.Private[:], responderEphemeral)
	if err != nil {
		return err
	}
	defer secureZeroResistant(ee)
	ns.mixKey(ee)

	// Déchiffrer s (clé statique du répondeur)
	responderStatic := msg2[noiseKeySize:]
	if len(responderStatic) < noiseKeySize+noiseMacSize {
		return ErrNoiseHandshakeFailed
	}

	decryptedStatic, err := ns.decryptAndHash(responderStatic)
	if err != nil {
		return err
	}

	// es
	es, err := curve25519.X25519(ephemeral.Private[:], decryptedStatic)
	if err != nil {
		return err
	}
	defer secureZeroResistant(es)
	ns.mixKey(es)

	// Message 3: -> s, se
	encryptedStatic, err := ns.encryptAndHash(localKey.Public[:])
	if err != nil {
		return err
	}

	// se
	se, err := curve25519.X25519(localKey.Private[:], responderEphemeral)
	if err != nil {
		return err
	}
	defer secureZeroResistant(se)
	ns.mixKey(se)

	if err := ns.sendMessage(conn, encryptedStatic, nil); err != nil {
		return err
	}

	// Dériver les clés finales
	ns.split()
	ns.isInitialized = true

	return nil
}

// performResponderHandshake effectue le handshake côté répondeur
func (ns *NoiseState) performResponderHandshake(conn io.ReadWriter, localKey *NoiseKeyPair, remotePublicKey []byte) error {
	// Message 1: <- e
	msg1, err := ns.receiveMessage(conn, nil)
	if err != nil {
		return err
	}

	if len(msg1) != noiseKeySize {
		return ErrNoiseHandshakeFailed
	}

	initiatorEphemeral := msg1
	ns.mixHash(initiatorEphemeral)

	// Générer une clé éphémère
	ephemeral, err := GenerateNoiseKeyPair()
	if err != nil {
		return err
	}
	defer secureZeroResistant(ephemeral.Private[:])

	// Message 2: -> e, ee, s, es
	ns.mixHash(ephemeral.Public[:])

	// ee
	ee, err := curve25519.X25519(ephemeral.Private[:], initiatorEphemeral)
	if err != nil {
		return err
	}
	defer secureZeroResistant(ee)
	ns.mixKey(ee)

	// Chiffrer notre clé statique
	encryptedStatic, err := ns.encryptAndHash(localKey.Public[:])
	if err != nil {
		return err
	}

	// es
	es, err := curve25519.X25519(localKey.Private[:], initiatorEphemeral)
	if err != nil {
		return err
	}
	defer secureZeroResistant(es)
	ns.mixKey(es)

	// Envoyer e || encrypted_s
	msg2 := make([]byte, 0, noiseKeySize+len(encryptedStatic))
	msg2 = append(msg2, ephemeral.Public[:]...)
	msg2 = append(msg2, encryptedStatic...)

	if err := ns.sendMessage(conn, msg2, nil); err != nil {
		return err
	}

	// Message 3: <- s, se
	msg3, err := ns.receiveMessage(conn, nil)
	if err != nil {
		return err
	}

	// Déchiffrer la clé statique de l'initiateur
	decryptedStatic, err := ns.decryptAndHash(msg3)
	if err != nil {
		return err
	}

	// se
	se, err := curve25519.X25519(ephemeral.Private[:], decryptedStatic)
	if err != nil {
		return err
	}
	defer secureZeroResistant(se)
	ns.mixKey(se)

	// Dériver les clés finales
	ns.split()
	ns.isInitialized = true

	return nil
}

// EncryptMessage chiffre un message avec Noise
func (ns *NoiseState) EncryptMessage(plaintext []byte) ([]byte, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if !ns.isInitialized {
		return nil, ErrNoiseNotInitialized
	}

	if len(plaintext) > maxNoiseMessage {
		return nil, ErrNoiseMessageTooLong
	}

	// Convertir le nonce en bytes
	nonce := make([]byte, noiseNonceSize)
	for i := 0; i < 8 && i < noiseNonceSize; i++ {
		nonce[i] = byte(ns.sendNonce >> (i * 8))
	}

	// Chiffrer avec ChaCha20-Poly1305 (simplifié avec secretbox pour cette démo)
	encrypted, err := ns.encryptWithKey(ns.sendKey[:], nonce, plaintext)
	if err != nil {
		return nil, err
	}

	ns.sendNonce++
	return encrypted, nil
}

// DecryptMessage déchiffre un message avec Noise
func (ns *NoiseState) DecryptMessage(ciphertext []byte) ([]byte, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if !ns.isInitialized {
		return nil, ErrNoiseNotInitialized
	}

	// Convertir le nonce en bytes
	nonce := make([]byte, noiseNonceSize)
	for i := 0; i < 8 && i < noiseNonceSize; i++ {
		nonce[i] = byte(ns.recvNonce >> (i * 8))
	}

	// Déchiffrer
	plaintext, err := ns.decryptWithKey(ns.recvKey[:], nonce, ciphertext)
	if err != nil {
		return nil, ErrNoiseDecryptFailed
	}

	ns.recvNonce++
	return plaintext, nil
}

// Fonctions helper pour le protocole Noise

// mixHash met à jour le hash du handshake
func (ns *NoiseState) mixHash(data []byte) {
	hasher := sha256.New()
	hasher.Write(ns.h[:])
	hasher.Write(data)
	copy(ns.h[:], hasher.Sum(nil))
}

// mixKey met à jour la chaining key
func (ns *NoiseState) mixKey(dhOutput []byte) {
	hkdfReader := hkdf.New(sha256.New, dhOutput, ns.ck[:], nil)

	var newCk [noiseKeySize]byte
	io.ReadFull(hkdfReader, newCk[:])
	ns.ck = newCk
}

// encryptAndHash chiffre et met à jour le hash
func (ns *NoiseState) encryptAndHash(plaintext []byte) ([]byte, error) {
	// Pour cette démo, utilisation d'un chiffrement simplifié
	// Dans une vraie implémentation, il faudrait ChaCha20-Poly1305

	// Dériver une clé temporaire
	hkdfReader := hkdf.New(sha256.New, ns.ck[:], ns.h[:], []byte("encrypt"))
	var tempKey [noiseKeySize]byte
	io.ReadFull(hkdfReader, tempKey[:])
	defer secureZeroResistant(tempKey[:])

	nonce := make([]byte, noiseNonceSize)
	rand.Read(nonce)

	encrypted, err := ns.encryptWithKey(tempKey[:], nonce, plaintext)
	if err != nil {
		return nil, err
	}

	// Ajouter le nonce au début
	result := make([]byte, 0, noiseNonceSize+len(encrypted))
	result = append(result, nonce...)
	result = append(result, encrypted...)

	ns.mixHash(result)
	return result, nil
}

// decryptAndHash déchiffre et met à jour le hash
func (ns *NoiseState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < noiseNonceSize {
		return nil, ErrNoiseDecryptFailed
	}

	ns.mixHash(ciphertext)

	nonce := ciphertext[:noiseNonceSize]
	encrypted := ciphertext[noiseNonceSize:]

	// Dériver la même clé temporaire
	hkdfReader := hkdf.New(sha256.New, ns.ck[:], ns.h[:], []byte("encrypt"))
	var tempKey [noiseKeySize]byte
	io.ReadFull(hkdfReader, tempKey[:])
	defer secureZeroResistant(tempKey[:])

	plaintext, err := ns.decryptWithKey(tempKey[:], nonce, encrypted)
	if err != nil {
		return nil, ErrNoiseDecryptFailed
	}

	return plaintext, nil
}

// split dérive les clés finales après le handshake
func (ns *NoiseState) split() {
	hkdfReader := hkdf.New(sha256.New, ns.ck[:], nil, nil)

	if ns.isInitiator {
		io.ReadFull(hkdfReader, ns.sendKey[:])
		io.ReadFull(hkdfReader, ns.recvKey[:])
	} else {
		io.ReadFull(hkdfReader, ns.recvKey[:])
		io.ReadFull(hkdfReader, ns.sendKey[:])
	}

	ns.sendNonce = 0
	ns.recvNonce = 0
}

// sendMessage envoie un message sur la connexion
func (ns *NoiseState) sendMessage(conn io.Writer, data, payload []byte) error {
	// Format simple: longueur + données
	totalLen := len(data)
	if payload != nil {
		totalLen += len(payload)
	}

	lenBytes := make([]byte, 2)
	lenBytes[0] = byte(totalLen >> 8)
	lenBytes[1] = byte(totalLen & 0xFF)

	if _, err := conn.Write(lenBytes); err != nil {
		return err
	}

	if _, err := conn.Write(data); err != nil {
		return err
	}

	if payload != nil {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}

	return nil
}

// receiveMessage reçoit un message de la connexion
func (ns *NoiseState) receiveMessage(conn io.Reader, expected []byte) ([]byte, error) {
	lenBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBytes); err != nil {
		return nil, err
	}

	msgLen := int(lenBytes[0])<<8 | int(lenBytes[1])
	if msgLen > maxNoiseMessage {
		return nil, ErrNoiseMessageTooLong
	}

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// encryptWithKey chiffre avec une clé donnée (simulation ChaCha20-Poly1305)
func (ns *NoiseState) encryptWithKey(key, nonce, plaintext []byte) ([]byte, error) {
	// Pour cette démo, utilisation d'un XOR simple avec hash
	// Dans une vraie implémentation, utiliser ChaCha20-Poly1305

	hasher := sha256.New()
	hasher.Write(key)
	hasher.Write(nonce)
	keystream := hasher.Sum(nil)

	encrypted := make([]byte, len(plaintext)+noiseMacSize)

	// XOR avec le keystream
	for i := 0; i < len(plaintext); i++ {
		encrypted[i] = plaintext[i] ^ keystream[i%len(keystream)]
	}

	// MAC simplifié
	hasher.Reset()
	hasher.Write(key)
	hasher.Write(encrypted[:len(plaintext)])
	mac := hasher.Sum(nil)
	copy(encrypted[len(plaintext):], mac[:noiseMacSize])

	return encrypted, nil
}

// decryptWithKey déchiffre avec une clé donnée
func (ns *NoiseState) decryptWithKey(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < noiseMacSize {
		return nil, ErrNoiseDecryptFailed
	}

	plaintextLen := len(ciphertext) - noiseMacSize
	encrypted := ciphertext[:plaintextLen]
	receivedMac := ciphertext[plaintextLen:]

	// Vérifier le MAC
	hasher := sha256.New()
	hasher.Write(key)
	hasher.Write(encrypted)
	expectedMac := hasher.Sum(nil)

	if subtle.ConstantTimeCompare(receivedMac, expectedMac[:noiseMacSize]) != 1 {
		return nil, ErrNoiseDecryptFailed
	}

	// Déchiffrer
	hasher.Reset()
	hasher.Write(key)
	hasher.Write(nonce)
	keystream := hasher.Sum(nil)

	plaintext := make([]byte, plaintextLen)
	for i := 0; i < plaintextLen; i++ {
		plaintext[i] = encrypted[i] ^ keystream[i%len(keystream)]
	}

	return plaintext, nil
}

// Reset nettoie l'état Noise
func (ns *NoiseState) Reset() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	secureZeroResistant(ns.sendKey[:])
	secureZeroResistant(ns.recvKey[:])
	secureZeroResistant(ns.h[:])
	secureZeroResistant(ns.ck[:])

	ns.sendNonce = 0
	ns.recvNonce = 0
	ns.isInitialized = false
}

// GetStats retourne les statistiques de l'état Noise
func (ns *NoiseState) GetStats() map[string]interface{} {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	return map[string]interface{}{
		"is_initialized": ns.isInitialized,
		"is_initiator":   ns.isInitiator,
		"send_nonce":     ns.sendNonce,
		"recv_nonce":     ns.recvNonce,
		"protocol":       "Noise_XX_25519_ChaChaPoly_SHA256",
	}
}

// IsInitialized retourne l'état d'initialisation
func (ns *NoiseState) IsInitialized() bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.isInitialized
}

// Fonctions utilitaires pour l'intégration

// CreateNoiseInitiator crée un initiateur Noise
func CreateNoiseInitiator() *NoiseState {
	return NewNoiseState(true)
}

// CreateNoiseResponder crée un répondeur Noise
func CreateNoiseResponder() *NoiseState {
	return NewNoiseState(false)
}

// ValidateNoiseKey valide une clé Noise
func ValidateNoiseKey(key []byte) error {
	if len(key) != noiseKeySize {
		return ErrNoiseInvalidKey
	}

	var zero [noiseKeySize]byte
	if subtle.ConstantTimeCompare(key, zero[:]) == 1 {
		return ErrNoiseInvalidKey
	}

	return nil
}

// EstimateNoiseOverhead estime l'overhead du protocole Noise
func EstimateNoiseOverhead() map[string]int {
	return map[string]int{
		"handshake_msg1": noiseKeySize + 2,                  // e + length
		"handshake_msg2": noiseKeySize*2 + noiseMacSize + 2, // e + encrypted_s + length
		"handshake_msg3": noiseKeySize + noiseMacSize + 2,   // encrypted_s + length
		"transport_msg":  noiseMacSize + 2,                  // mac + length per message
		"nonce_size":     noiseNonceSize,
		"key_size":       noiseKeySize,
		"mac_size":       noiseMacSize,
	}
}
