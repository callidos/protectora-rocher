package communication

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
	maxSkippedMessages = 100
	keySize            = 32
	maxSkippedKeysSize = 1000
	maxIdentifierLen   = 64 // Nouvelle limite pour les identifiants
)

var (
	ErrTooManySkippedMessages = errors.New("too many skipped messages")
	ErrChainKeyNotInitialized = errors.New("chain key not initialized")
	ErrInvalidDHKey           = errors.New("invalid DH key")
	ErrRatchetLocked          = errors.New("ratchet is locked")
	ErrInvalidIdentifier      = errors.New("invalid identifier")
)

// Points interdits pour Curve25519 selon RFC 7748
var forbiddenPoints = [][32]byte{
	{},  // Point zéro
	{1}, // Point 1
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00}, // Order 8
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57}, // Order 4
}

// DHKeyPair représente une paire de clés Curve25519
type DHKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateDHKeyPair génère une nouvelle paire de clés Curve25519
func GenerateDHKeyPair() (*DHKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}

	// Forcer les bits selon RFC 7748
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return &DHKeyPair{Private: priv, Public: pub}, nil
}

// validateDHPublicKey valide qu'une clé publique DH est sécurisée selon RFC 7748
func validateDHPublicKey(pubKey [32]byte) bool {
	// Vérification des points interdits
	for _, forbidden := range forbiddenPoints {
		if subtle.ConstantTimeCompare(pubKey[:], forbidden[:]) == 1 {
			return false
		}
	}

	// Vérification que le point produit un secret DH non-zéro
	var testPriv [32]byte
	if _, err := rand.Read(testPriv[:]); err != nil {
		return false
	}

	// Forcer les bits selon RFC 7748
	testPriv[0] &= 248
	testPriv[31] &= 127
	testPriv[31] |= 64

	result, err := curve25519.X25519(testPriv[:], pubKey[:])
	if err != nil {
		return false
	}

	var zero [32]byte
	return subtle.ConstantTimeCompare(result, zero[:]) != 1
}

// validateIdentifier valide un identifiant de message sauté
func validateIdentifier(id string) bool {
	if len(id) == 0 || len(id) > maxIdentifierLen {
		return false
	}

	// Vérifier que l'identifiant ne contient que des caractères sûrs
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':') {
			return false
		}
	}
	return true
}

// DoubleRatchet implémente le protocole Double Ratchet avec sécurité renforcée
type DoubleRatchet struct {
	mu sync.RWMutex

	// État du ratchet racine
	rootKey [32]byte

	// Chaînes de clés symétriques
	sendingChainKey   [32]byte
	receivingChainKey [32]byte

	// Compteurs
	sendMsgNum uint32
	recvMsgNum uint32
	prevMsgNum uint32

	// Clés DH
	dhSelf   *DHKeyPair
	dhRemote [32]byte

	// Messages sautés avec validation d'identifiants
	skippedKeys    map[string][32]byte
	skippedKeysLen int

	// État d'initialisation
	sendingChainInitialized   bool
	receivingChainInitialized bool
	isServer                  bool
	isLocked                  bool
}

// InitializeDoubleRatchet initialise le ratchet avec validation renforcée
func InitializeDoubleRatchet(sessionKey []byte, ourDH *DHKeyPair, remoteDHPublic [32]byte) (*DoubleRatchet, error) {
	if len(sessionKey) < 32 {
		return nil, errors.New("session key too short")
	}
	if ourDH == nil {
		return nil, errors.New("DH keypair required")
	}

	// Validation stricte de la clé publique distante
	if !validateDHPublicKey(remoteDHPublic) {
		return nil, ErrInvalidDHKey
	}

	// Validation de notre propre clé publique
	if !validateDHPublicKey(ourDH.Public) {
		return nil, ErrInvalidDHKey
	}

	dr := &DoubleRatchet{
		dhSelf:         ourDH,
		dhRemote:       remoteDHPublic,
		skippedKeys:    make(map[string][32]byte),
		skippedKeysLen: 0,
	}

	// Initialiser la clé racine avec dérivation sécurisée
	copy(dr.rootKey[:], sessionKey[:32])

	return dr, nil
}

// RatchetEncrypt génère une clé de message pour le chiffrement
func (dr *DoubleRatchet) RatchetEncrypt() ([]byte, error) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if dr.isLocked {
		return nil, ErrRatchetLocked
	}

	if !dr.sendingChainInitialized {
		if err := dr.initializeSendingChainUnsafe(); err != nil {
			return nil, err
		}
	}

	// Dériver la clé de message
	messageKey, err := dr.deriveMessageKeyUnsafe(dr.sendingChainKey[:], dr.sendMsgNum)
	if err != nil {
		return nil, err
	}

	// Avancer la chaîne d'envoi
	dr.sendingChainKey = dr.advanceChainKeyUnsafe(dr.sendingChainKey)
	dr.sendMsgNum++

	return messageKey[:], nil
}

// RatchetDecrypt génère une clé de message pour le déchiffrement
func (dr *DoubleRatchet) RatchetDecrypt() ([]byte, error) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if dr.isLocked {
		return nil, ErrRatchetLocked
	}

	if !dr.receivingChainInitialized {
		if err := dr.initializeReceivingChainUnsafe(); err != nil {
			return nil, err
		}
	}

	// Dériver la clé de message
	messageKey, err := dr.deriveMessageKeyUnsafe(dr.receivingChainKey[:], dr.recvMsgNum)
	if err != nil {
		return nil, err
	}

	// Avancer la chaîne de réception
	dr.receivingChainKey = dr.advanceChainKeyUnsafe(dr.receivingChainKey)
	dr.recvMsgNum++

	return messageKey[:], nil
}

// initializeSendingChainUnsafe initialise la chaîne d'envoi (non thread-safe)
func (dr *DoubleRatchet) initializeSendingChainUnsafe() error {
	dhSecret, err := curve25519.X25519(dr.dhSelf.Private[:], dr.dhRemote[:])
	if err != nil {
		return err
	}
	defer secureZero(dhSecret)

	// Vérifier que le secret DH n'est pas zéro
	var zero [32]byte
	if subtle.ConstantTimeCompare(dhSecret, zero[:]) == 1 {
		return ErrInvalidDHKey
	}

	// Dériver la clé de chaîne d'envoi
	chainKey, err := dr.deriveChainKeyUnsafe(dhSecret, []byte("sending-chain"))
	if err != nil {
		return err
	}

	dr.sendingChainKey = chainKey
	dr.sendingChainInitialized = true
	dr.sendMsgNum = 0

	return nil
}

// initializeReceivingChainUnsafe initialise la chaîne de réception (non thread-safe)
func (dr *DoubleRatchet) initializeReceivingChainUnsafe() error {
	dhSecret, err := curve25519.X25519(dr.dhSelf.Private[:], dr.dhRemote[:])
	if err != nil {
		return err
	}
	defer secureZero(dhSecret)

	// Vérifier que le secret DH n'est pas zéro
	var zero [32]byte
	if subtle.ConstantTimeCompare(dhSecret, zero[:]) == 1 {
		return ErrInvalidDHKey
	}

	// Dériver la clé de chaîne de réception
	chainKey, err := dr.deriveChainKeyUnsafe(dhSecret, []byte("receiving-chain"))
	if err != nil {
		return err
	}

	dr.receivingChainKey = chainKey
	dr.receivingChainInitialized = true
	dr.recvMsgNum = 0

	return nil
}

// deriveChainKeyUnsafe dérive une clé de chaîne (non thread-safe)
func (dr *DoubleRatchet) deriveChainKeyUnsafe(input []byte, info []byte) ([32]byte, error) {
	h := hkdf.New(sha256.New, input, dr.rootKey[:], info)
	var key [32]byte
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

// deriveMessageKeyUnsafe dérive une clé de message (non thread-safe)
func (dr *DoubleRatchet) deriveMessageKeyUnsafe(chainKey []byte, msgNum uint32) ([32]byte, error) {
	// Créer l'info avec le numéro de message en big-endian
	info := make([]byte, len("message-key-")+4)
	copy(info, "message-key-")
	info[12] = byte(msgNum >> 24)
	info[13] = byte(msgNum >> 16)
	info[14] = byte(msgNum >> 8)
	info[15] = byte(msgNum)

	h := hkdf.New(sha256.New, chainKey, nil, info)
	var key [32]byte
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

// advanceChainKeyUnsafe fait avancer la clé de chaîne (non thread-safe)
func (dr *DoubleRatchet) advanceChainKeyUnsafe(chainKey [32]byte) [32]byte {
	h := hkdf.New(sha256.New, chainKey[:], nil, []byte("chain-advance"))
	var newKey [32]byte
	_, _ = io.ReadFull(h, newKey[:])
	return newKey
}

// PerformDHRatchet effectue un pas de ratchet DH avec validation stricte
func (dr *DoubleRatchet) PerformDHRatchet(newRemotePub [32]byte) error {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if dr.isLocked {
		return ErrRatchetLocked
	}

	// Validation stricte de la nouvelle clé publique
	if !validateDHPublicKey(newRemotePub) {
		return ErrInvalidDHKey
	}

	// Sauvegarder l'état précédent
	dr.prevMsgNum = dr.sendMsgNum
	dr.sendMsgNum = 0
	dr.recvMsgNum = 0

	// Mettre à jour la clé publique distante
	dr.dhRemote = newRemotePub

	// Générer une nouvelle paire DH
	newDH, err := GenerateDHKeyPair()
	if err != nil {
		return err
	}

	// Calculer le nouveau secret DH
	dhSecret, err := curve25519.X25519(newDH.Private[:], newRemotePub[:])
	if err != nil {
		return err
	}
	defer secureZero(dhSecret)

	// Vérifier que le secret DH n'est pas zéro
	var zero [32]byte
	if subtle.ConstantTimeCompare(dhSecret, zero[:]) == 1 {
		return ErrInvalidDHKey
	}

	// Dériver la nouvelle clé racine et clé de chaîne de réception
	newRootKey, err := dr.deriveChainKeyUnsafe(dhSecret, []byte("root-key"))
	if err != nil {
		return err
	}

	newReceivingChain, err := dr.deriveChainKeyUnsafe(dhSecret, []byte("receiving-chain"))
	if err != nil {
		return err
	}

	// Nettoyage sécurisé de l'ancienne clé DH
	if dr.dhSelf != nil {
		secureZero(dr.dhSelf.Private[:])
		secureZero(dr.dhSelf.Public[:])
	}

	// Mettre à jour l'état
	dr.rootKey = newRootKey
	dr.receivingChainKey = newReceivingChain
	dr.receivingChainInitialized = true
	dr.dhSelf = newDH

	// Réinitialiser la chaîne d'envoi
	return dr.initializeSendingChainUnsafe()
}

// TrySkippedMessageKeys tente de déchiffrer avec des clés stockées
func (dr *DoubleRatchet) TrySkippedMessageKeys(identifier string) ([]byte, bool) {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if dr.isLocked {
		return nil, false
	}

	// Validation de l'identifiant
	if !validateIdentifier(identifier) {
		return nil, false
	}

	key, exists := dr.skippedKeys[identifier]
	if exists {
		delete(dr.skippedKeys, identifier)
		dr.skippedKeysLen--
		return key[:], true
	}
	return nil, false
}

// StoreSkippedMessageKey stocke une clé pour un message sauté avec validation
func (dr *DoubleRatchet) StoreSkippedMessageKey(identifier string, key []byte) error {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	if dr.isLocked {
		return ErrRatchetLocked
	}

	// Validation de l'identifiant
	if !validateIdentifier(identifier) {
		return ErrInvalidIdentifier
	}

	if dr.skippedKeysLen >= maxSkippedKeysSize {
		return ErrTooManySkippedMessages
	}

	if len(key) != 32 {
		return errors.New("invalid key size")
	}

	var keyArray [32]byte
	copy(keyArray[:], key)

	// Si la clé existe déjà, on ne compte pas double
	if _, exists := dr.skippedKeys[identifier]; !exists {
		dr.skippedKeysLen++
	}

	dr.skippedKeys[identifier] = keyArray
	return nil
}

// Reset réinitialise l'état du ratchet de manière sécurisée
func (dr *DoubleRatchet) Reset() {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	// Verrouiller pour empêcher l'utilisation pendant le reset
	dr.isLocked = true

	// Nettoyage sécurisé de toutes les clés
	secureZero(dr.rootKey[:])
	secureZero(dr.sendingChainKey[:])
	secureZero(dr.receivingChainKey[:])

	// Nettoyage sécurisé des clés sautées
	for id, key := range dr.skippedKeys {
		secureZero(key[:])
		delete(dr.skippedKeys, id)
	}
	dr.skippedKeysLen = 0

	// Nettoyage des clés DH
	if dr.dhSelf != nil {
		secureZero(dr.dhSelf.Private[:])
		secureZero(dr.dhSelf.Public[:])
		dr.dhSelf = nil
	}
	secureZero(dr.dhRemote[:])

	// Réinitialisation des compteurs
	dr.sendMsgNum = 0
	dr.recvMsgNum = 0
	dr.prevMsgNum = 0
	dr.sendingChainInitialized = false
	dr.receivingChainInitialized = false

	// Déverrouiller
	dr.isLocked = false
}

// GetPublicKey retourne la clé publique DH actuelle de manière thread-safe
func (dr *DoubleRatchet) GetPublicKey() [32]byte {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	if dr.dhSelf != nil {
		return dr.dhSelf.Public
	}
	return [32]byte{}
}

// GetStats retourne les statistiques du ratchet de manière thread-safe
func (dr *DoubleRatchet) GetStats() map[string]interface{} {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	return map[string]interface{}{
		"send_msg_num":                dr.sendMsgNum,
		"recv_msg_num":                dr.recvMsgNum,
		"prev_msg_num":                dr.prevMsgNum,
		"skipped_keys_count":          dr.skippedKeysLen,
		"sending_chain_initialized":   dr.sendingChainInitialized,
		"receiving_chain_initialized": dr.receivingChainInitialized,
		"is_locked":                   dr.isLocked,
	}
}
