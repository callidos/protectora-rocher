package communication

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DoubleRatchet contient l'état du double ratchet utilisé pour faire évoluer les clés de chiffrement.
type DoubleRatchet struct {
	RootKey        []byte // Clé racine dérivée de la clé de session.
	SendingChain   []byte // Chaîne d'envoi pour dériver les clés de message sortantes.
	ReceivingChain []byte // Chaîne de réception pour dériver les clés de message entrantes.
}

// InitializeDoubleRatchet initialise l'état du double ratchet à partir d'une clé de session.
func InitializeDoubleRatchet(sessionKey []byte) (*DoubleRatchet, error) {
	if len(sessionKey) == 0 {
		return nil, errors.New("session key cannot be empty")
	}
	rootKey := make([]byte, 32)
	sendingChain := make([]byte, 32)
	receivingChain := make([]byte, 32)

	// Dériver la clé racine.
	hkdfRoot := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Root"))
	if _, err := io.ReadFull(hkdfRoot, rootKey); err != nil {
		return nil, err
	}
	// Dériver la chaîne d'envoi.
	hkdfSend := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Sending"))
	if _, err := io.ReadFull(hkdfSend, sendingChain); err != nil {
		return nil, err
	}
	// Dériver la chaîne de réception.
	hkdfRecv := hkdf.New(sha256.New, sessionKey, nil, []byte("DoubleRatchet-Receiving"))
	if _, err := io.ReadFull(hkdfRecv, receivingChain); err != nil {
		return nil, err
	}
	return &DoubleRatchet{
		RootKey:        rootKey,
		SendingChain:   sendingChain,
		ReceivingChain: receivingChain,
	}, nil
}

// RatchetEncrypt dérive une clé de message à partir de la chaîne d'envoi, met à jour cette chaîne, et retourne la clé de message.
func (dr *DoubleRatchet) RatchetEncrypt() (messageKey []byte, newChainKey []byte, err error) {
	hkdfMsg := hkdf.New(sha256.New, dr.SendingChain, nil, []byte("DoubleRatchet-MessageKey"))
	messageKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfMsg, messageKey); err != nil {
		return nil, nil, err
	}
	hkdfChain := hkdf.New(sha256.New, dr.SendingChain, nil, []byte("DoubleRatchet-ChainUpdate"))
	newChainKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfChain, newChainKey); err != nil {
		return nil, nil, err
	}
	dr.SendingChain = newChainKey
	return messageKey, newChainKey, nil
}

// RatchetDecrypt dérive une clé de message à partir de la chaîne de réception, met à jour cette chaîne, et retourne la clé de message.
func (dr *DoubleRatchet) RatchetDecrypt() (messageKey []byte, newChainKey []byte, err error) {
	hkdfMsg := hkdf.New(sha256.New, dr.ReceivingChain, nil, []byte("DoubleRatchet-MessageKey"))
	messageKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfMsg, messageKey); err != nil {
		return nil, nil, err
	}
	hkdfChain := hkdf.New(sha256.New, dr.ReceivingChain, nil, []byte("DoubleRatchet-ChainUpdate"))
	newChainKey = make([]byte, 32)
	if _, err = io.ReadFull(hkdfChain, newChainKey); err != nil {
		return nil, nil, err
	}
	dr.ReceivingChain = newChainKey
	return messageKey, newChainKey, nil
}
