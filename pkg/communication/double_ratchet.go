package communication

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

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

// DoubleRatchet contient l'état du double ratchet selon la spécification Signal.
type DoubleRatchet struct {
	// État du ratchet racine
	RootKey []byte // RK dans la spec

	// Chaînes de clés symétriques
	SendingChainKey   []byte // CKs dans la spec
	ReceivingChainKey []byte // CKr dans la spec

	// Compteurs de messages
	SendMsgNum uint32 // Ns dans la spec
	RecvMsgNum uint32 // Nr dans la spec
	PrevMsgNum uint32 // PN dans la spec

	// Paires de clés DH
	DHSelf   *DHKeyPair // notre paire DH actuelle
	DHRemote [32]byte   // clé publique DH distante

	// Gestion des messages sautés
	SkippedMessageKeys map[string][]byte

	// Métadonnées
	IsServer bool
}

// InitializeDoubleRatchet initialise le ratchet selon la spécification Signal.
// Pour Alice (initiateur): elle a sa paire DH et la clé publique de Bob
// Pour Bob (récepteur): il a sa paire DH et recevra la clé publique d'Alice
func InitializeDoubleRatchet(sessionKey []byte, ourDH *DHKeyPair, remoteDHPublic [32]byte) (*DoubleRatchet, error) {
	if len(sessionKey) == 0 {
		return nil, errors.New("session key cannot be empty")
	}

	dr := &DoubleRatchet{
		RootKey:            make([]byte, 32),
		SendingChainKey:    make([]byte, 32),
		ReceivingChainKey:  nil, // Sera initialisé lors du premier DH ratchet
		SendMsgNum:         0,
		RecvMsgNum:         0,
		PrevMsgNum:         0,
		DHSelf:             ourDH,
		DHRemote:           remoteDHPublic,
		SkippedMessageKeys: make(map[string][]byte),
		IsServer:           false,
	}

	// Initialiser la clé racine avec la clé de session
	copy(dr.RootKey, sessionKey[:32])

	// CORRECTION MAJEURE: Initialisation différente selon le rôle
	// Alice (client) initialise sa chaîne d'envoi
	// Bob (serveur) attend le premier message d'Alice pour initialiser ses chaînes
	if !dr.IsServer {
		// Alice initialise sa chaîne d'envoi
		sendingChainKey, err := dr.kdfChainKey(dr.RootKey, []byte("chain-sending-init"))
		if err != nil {
			return nil, err
		}
		dr.SendingChainKey = sendingChainKey
	}

	return dr, nil
}

// kdfChainKey dérive une nouvelle clé de chaîne selon la spécification
func (dr *DoubleRatchet) kdfChainKey(inputKey []byte, info []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, inputKey, nil, info)
	output := make([]byte, 32)
	if _, err := io.ReadFull(h, output); err != nil {
		return nil, err
	}
	return output, nil
}

// kdfMessageKey dérive une clé de message à partir d'une clé de chaîne
func (dr *DoubleRatchet) kdfMessageKey(chainKey []byte) (newChainKey, messageKey []byte, err error) {
	// Dériver la clé de message
	messageKey, err = dr.kdfChainKey(chainKey, []byte("message-key"))
	if err != nil {
		return nil, nil, err
	}

	// Dériver la nouvelle clé de chaîne
	newChainKey, err = dr.kdfChainKey(chainKey, []byte("chain-key"))
	if err != nil {
		return nil, nil, err
	}

	return newChainKey, messageKey, nil
}

// dhRatchet effectue un pas de ratchet DH selon la spécification Signal
func (dr *DoubleRatchet) dhRatchet(newRemotePub [32]byte) error {
	// Sauvegarder le nombre de messages de la chaîne d'envoi précédente
	dr.PrevMsgNum = dr.SendMsgNum

	// Reset des compteurs
	dr.SendMsgNum = 0
	dr.RecvMsgNum = 0

	// Mettre à jour la clé publique distante
	dr.DHRemote = newRemotePub

	// Calculer le nouvel échange DH
	sharedSecret, err := curve25519.X25519(dr.DHSelf.Private[:], newRemotePub[:])
	if err != nil {
		return err
	}

	// CORRECTION: Utiliser KDF avec la clé racine existante comme salt
	h := hkdf.New(sha256.New, sharedSecret, dr.RootKey, []byte("ratchet-root"))

	// Dériver nouvelle clé racine et clé de chaîne de réception
	newRootKey := make([]byte, 32)
	if _, err := io.ReadFull(h, newRootKey); err != nil {
		return err
	}

	newReceivingChainKey := make([]byte, 32)
	if _, err := io.ReadFull(h, newReceivingChainKey); err != nil {
		return err
	}

	// Mettre à jour l'état
	dr.RootKey = newRootKey
	dr.ReceivingChainKey = newReceivingChainKey

	// Générer nouvelle paire DH pour les futurs échanges
	newDH, err := GenerateDHKeyPair()
	if err != nil {
		return err
	}

	// Calculer le nouvel échange DH avec notre nouvelle clé
	sharedSecret2, err := curve25519.X25519(newDH.Private[:], newRemotePub[:])
	if err != nil {
		return err
	}

	// Dériver la nouvelle clé de chaîne d'envoi
	h2 := hkdf.New(sha256.New, sharedSecret2, dr.RootKey, []byte("ratchet-sending"))

	newRootKey2 := make([]byte, 32)
	if _, err := io.ReadFull(h2, newRootKey2); err != nil {
		return err
	}

	newSendingChainKey := make([]byte, 32)
	if _, err := io.ReadFull(h2, newSendingChainKey); err != nil {
		return err
	}

	// Mettre à jour l'état final
	dr.RootKey = newRootKey2
	dr.SendingChainKey = newSendingChainKey
	dr.DHSelf = newDH

	return nil
}

// RatchetEncrypt dérive une clé de message pour l'envoi
func (dr *DoubleRatchet) RatchetEncrypt() ([]byte, error) {
	if dr.SendingChainKey == nil {
		return nil, errors.New("sending chain key not initialized")
	}

	newChainKey, messageKey, err := dr.kdfMessageKey(dr.SendingChainKey)
	if err != nil {
		return nil, err
	}

	dr.SendingChainKey = newChainKey
	dr.SendMsgNum++

	return messageKey, nil
}

// RatchetDecrypt dérive une clé de message pour la réception
func (dr *DoubleRatchet) RatchetDecrypt() ([]byte, error) {
	if dr.ReceivingChainKey == nil {
		return nil, errors.New("receiving chain key not initialized")
	}

	newChainKey, messageKey, err := dr.kdfMessageKey(dr.ReceivingChainKey)
	if err != nil {
		return nil, err
	}

	dr.ReceivingChainKey = newChainKey
	dr.RecvMsgNum++

	return messageKey, nil
}

// TrySkippedMessageKeys tente de déchiffrer avec des clés de messages sautés
func (dr *DoubleRatchet) TrySkippedMessageKeys(identifier string) ([]byte, bool) {
	key, exists := dr.SkippedMessageKeys[identifier]
	if exists {
		delete(dr.SkippedMessageKeys, identifier)
		return key, true
	}
	return nil, false
}

// SkipMessageKeys génère et stocke les clés pour les messages sautés
func (dr *DoubleRatchet) SkipMessageKeys(untilMsgNum uint32) error {
	if dr.RecvMsgNum+100 < untilMsgNum {
		return errors.New("too many skipped messages")
	}

	if dr.ReceivingChainKey == nil {
		return errors.New("receiving chain key not initialized")
	}

	chainKey := make([]byte, len(dr.ReceivingChainKey))
	copy(chainKey, dr.ReceivingChainKey)

	for i := dr.RecvMsgNum; i < untilMsgNum; i++ {
		newChainKey, messageKey, err := dr.kdfMessageKey(chainKey)
		if err != nil {
			return err
		}

		// Stocker la clé du message sauté
		identifier := fmt.Sprintf("%x-%d", dr.DHRemote, i)
		dr.SkippedMessageKeys[identifier] = messageKey

		chainKey = newChainKey
	}

	dr.ReceivingChainKey = chainKey
	dr.RecvMsgNum = untilMsgNum

	return nil
}

// GetSkippedMessageKey et StoreSkippedMessageKey pour compatibilité
func (dr *DoubleRatchet) GetSkippedMessageKey(identifier string) ([]byte, bool) {
	return dr.TrySkippedMessageKeys(identifier)
}

func (dr *DoubleRatchet) StoreSkippedMessageKey(identifier string, key []byte) {
	dr.SkippedMessageKeys[identifier] = key
}
