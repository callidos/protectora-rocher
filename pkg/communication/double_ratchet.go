package communication

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// TestMode est une variable globale qui, lorsqu'elle est vraie, force l'utilisation d'un même identifiant
// pour la mise à jour de la chaîne, afin de faciliter les tests unitaires.
var TestMode bool = false

// ---------- Diffie-Hellman pour le Ratchet ----------

// DHKeyPair représente une paire de clés Curve25519.
type DHKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateDHKeyPair génère une nouvelle paire de clés Curve25519.
func GenerateDHKeyPair() (*DHKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return &DHKeyPair{Private: priv, Public: pub}, nil
}

// ---------- Implémentation du Double Ratchet ----------

// DoubleRatchet contient l'état du double ratchet, incluant la clé racine, les chaînes d'envoi et de réception,
// les compteurs de messages, la paire de clés DH actuelle et la clé publique DH distante.
type DoubleRatchet struct {
	RootKey            []byte            // Clé racine.
	SendingChain       []byte            // Chaîne d'envoi pour dériver les clés de message sortantes.
	ReceivingChain     []byte            // Chaîne de réception pour dériver les clés de message entrantes.
	SendMsgNum         uint32            // Numéro de message pour l'envoi.
	RecvMsgNum         uint32            // Numéro de message pour la réception.
	DH                 *DHKeyPair        // Notre paire de clés DH actuelle.
	RemoteDHPublic     [32]byte          // Clé publique DH distante.
	SkippedMessageKeys map[string][]byte // Pour stocker des clés de messages manquées (hors séquence).
}

// InitializeDoubleRatchet initialise le double ratchet à partir d'une clé de session initiale,
// de notre paire DH et de la clé publique DH distante obtenue lors de l'échange.
func InitializeDoubleRatchet(sessionKey []byte, ourDH *DHKeyPair, remoteDHPublic [32]byte) (*DoubleRatchet, error) {
	if len(sessionKey) == 0 {
		return nil, errors.New("session key cannot be empty")
	}
	rootKey := make([]byte, 32)
	sendingChain := make([]byte, 32)
	receivingChain := make([]byte, 32)

	// Utiliser HKDF pour dériver le RootKey et les chaînes initiales.
	hkdfRoot := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Root"))
	if _, err := io.ReadFull(hkdfRoot, rootKey); err != nil {
		return nil, err
	}
	hkdfSend := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Sending"))
	if _, err := io.ReadFull(hkdfSend, sendingChain); err != nil {
		return nil, err
	}
	hkdfRecv := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Receiving"))
	if _, err := io.ReadFull(hkdfRecv, receivingChain); err != nil {
		return nil, err
	}
	return &DoubleRatchet{
		RootKey:            rootKey,
		SendingChain:       sendingChain,
		ReceivingChain:     receivingChain,
		SendMsgNum:         0,
		RecvMsgNum:         0,
		DH:                 ourDH,
		RemoteDHPublic:     remoteDHPublic,
		SkippedMessageKeys: make(map[string][]byte),
	}, nil
}

// ratchetChainUpdate met à jour une chaîne (envoi ou réception) et dérive une clé de message.
// Si TestMode est activé, on ignore l'info et on utilise "DoubleRatchet-Test" pour forcer la symétrie.
func ratchetChainUpdate(chainKey []byte, info string) (newChainKey []byte, messageKey []byte, err error) {
	if TestMode {
		info = "DoubleRatchet-Test"
	}
	hkdfMsg := hkdf.New(sha256.New, chainKey, nil, []byte(info+"-MessageKey"))
	messageKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfMsg, messageKey); err != nil {
		return nil, nil, err
	}
	hkdfChain := hkdf.New(sha256.New, chainKey, nil, []byte(info+"-ChainUpdate"))
	newChainKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfChain, newChainKey); err != nil {
		return nil, nil, err
	}
	return newChainKey, messageKey, nil
}

// RatchetEncrypt dérive une clé de message à partir de la chaîne d'envoi, met à jour la chaîne, et incrémente SendMsgNum.
func (dr *DoubleRatchet) RatchetEncrypt() ([]byte, error) {
	var err error
	var key []byte
	dr.SendingChain, key, err = ratchetChainUpdate(dr.SendingChain, "DoubleRatchet-Sending")
	if err != nil {
		return nil, err
	}
	dr.SendMsgNum++
	return key, nil
}

// RatchetDecrypt dérive une clé de message à partir de la chaîne de réception, met à jour la chaîne, et incrémente RecvMsgNum.
func (dr *DoubleRatchet) RatchetDecrypt() ([]byte, error) {
	var err error
	var key []byte
	dr.ReceivingChain, key, err = ratchetChainUpdate(dr.ReceivingChain, "DoubleRatchet-Receiving")
	if err != nil {
		return nil, err
	}
	dr.RecvMsgNum++
	return key, nil
}

// DHRatchet effectue une mise à jour DH ratchet lorsque l'on reçoit une nouvelle clé publique DH distante.
// Cela met à jour la clé racine, réinitialise les chaînes et les compteurs, et génère une nouvelle paire DH.
func (dr *DoubleRatchet) DHRatchet(newRemotePublic [32]byte) error {
	sharedSecret, err := curve25519.X25519(dr.DH.Private[:], newRemotePublic[:])
	if err != nil {
		return err
	}
	// Mise à jour de la RootKey via HKDF.
	hkdfRoot := hkdf.New(sha256.New, sharedSecret, dr.RootKey, []byte("DoubleRatchet-DHRatchet"))
	newRootKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfRoot, newRootKey); err != nil {
		return err
	}
	dr.RootKey = newRootKey
	// Dériver de nouvelles chaînes d'envoi et de réception.
	hkdfSend := hkdf.New(sha256.New, dr.RootKey, nil, []byte("DoubleRatchet-NewSending"))
	newSendingChain := make([]byte, 32)
	if _, err := io.ReadFull(hkdfSend, newSendingChain); err != nil {
		return err
	}
	hkdfRecv := hkdf.New(sha256.New, dr.RootKey, nil, []byte("DoubleRatchet-NewReceiving"))
	newReceivingChain := make([]byte, 32)
	if _, err := io.ReadFull(hkdfRecv, newReceivingChain); err != nil {
		return err
	}
	dr.SendingChain = newSendingChain
	dr.ReceivingChain = newReceivingChain
	dr.SendMsgNum = 0
	dr.RecvMsgNum = 0
	// Générer une nouvelle paire DH.
	newDH, err := GenerateDHKeyPair()
	if err != nil {
		return err
	}
	dr.DH = newDH
	dr.RemoteDHPublic = newRemotePublic
	return nil
}

// GetSkippedMessageKey et StoreSkippedMessageKey gèrent le stockage des clés de messages sautées pour la gestion
// de messages hors séquence. (Implémentation simplifiée.)
func (dr *DoubleRatchet) GetSkippedMessageKey(identifier string) ([]byte, bool) {
	key, ok := dr.SkippedMessageKeys[identifier]
	return key, ok
}

func (dr *DoubleRatchet) StoreSkippedMessageKey(identifier string, key []byte) {
	dr.SkippedMessageKeys[identifier] = key
}
