// key_exchange.go
package rocher

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

var (
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrKeyGeneration  = errors.New("key generation failed")
	ErrEncapsulation  = errors.New("encapsulation failed")
	ErrDecapsulation  = errors.New("decapsulation failed")
)

// KyberKeyExchange gère l'échange de clés avec Kyber768
type KyberKeyExchange struct{}

// NewKyberKeyExchange crée une nouvelle instance d'échange de clés
func NewKyberKeyExchange() *KyberKeyExchange {
	return &KyberKeyExchange{}
}

// GenerateKeyPair génère une paire de clés Kyber768
func (kke *KyberKeyExchange) GenerateKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, ErrKeyGeneration
	}

	// Sérialiser les clés
	pubBytes := make([]byte, kyber768.PublicKeySize)
	publicKey.Pack(pubBytes)

	privBytes := make([]byte, kyber768.PrivateKeySize)
	privateKey.Pack(privBytes)

	return pubBytes, privBytes, nil
}

// Encapsulate génère un secret partagé et un ciphertext (côté expéditeur)
func (kke *KyberKeyExchange) Encapsulate(publicKeyBytes []byte) ([]byte, []byte, error) {
	if len(publicKeyBytes) != kyber768.PublicKeySize {
		return nil, nil, ErrInvalidKeySize
	}

	// Créer une clé publique Kyber768 directe
	var publicKey kyber768.PublicKey
	publicKey.Unpack(publicKeyBytes)

	// Encapsuler
	ciphertext := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)

	publicKey.EncapsulateTo(ciphertext, sharedSecret, nil) // nil = utilise crypto/rand

	return ciphertext, sharedSecret, nil
}

// Decapsulate récupère le secret partagé à partir du ciphertext (côté destinataire)
func (kke *KyberKeyExchange) Decapsulate(privateKeyBytes, ciphertext []byte) ([]byte, error) {
	if len(privateKeyBytes) != kyber768.PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	// Créer une clé privée Kyber768 directe
	var privateKey kyber768.PrivateKey
	privateKey.Unpack(privateKeyBytes)

	// Décapsuler
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	privateKey.DecapsulateTo(sharedSecret, ciphertext)

	// Vérifier que le secret n'est pas zéro
	if isAllZeros(sharedSecret) {
		return nil, ErrDecapsulation
	}

	return sharedSecret, nil
}

// PerformKeyExchange effectue un échange de clés complet sur une connexion
func (kke *KyberKeyExchange) PerformKeyExchange(conn io.ReadWriter, isInitiator bool) ([]byte, error) {
	if isInitiator {
		return kke.initiatorExchange(conn)
	}
	return kke.responderExchange(conn)
}

// initiatorExchange gère l'échange côté initiateur
func (kke *KyberKeyExchange) initiatorExchange(conn io.ReadWriter) ([]byte, error) {
	// 1. Recevoir la clé publique du destinataire
	publicKey, err := kke.receivePublicKey(conn)
	if err != nil {
		return nil, err
	}

	// 2. Encapsuler pour obtenir le secret partagé
	ciphertext, sharedSecret, err := kke.Encapsulate(publicKey)
	if err != nil {
		return nil, err
	}

	// 3. Envoyer le ciphertext
	if err := kke.sendCiphertext(conn, ciphertext); err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// responderExchange gère l'échange côté destinataire
func (kke *KyberKeyExchange) responderExchange(conn io.ReadWriter) ([]byte, error) {
	// 1. Générer une paire de clés
	publicKey, privateKey, err := kke.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// 2. Envoyer la clé publique
	if err := kke.sendPublicKey(conn, publicKey); err != nil {
		return nil, err
	}

	// 3. Recevoir le ciphertext
	ciphertext, err := kke.receiveCiphertext(conn)
	if err != nil {
		return nil, err
	}

	// 4. Décapsuler pour obtenir le secret partagé
	sharedSecret, err := kke.Decapsulate(privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// sendPublicKey envoie une clé publique sur la connexion
func (kke *KyberKeyExchange) sendPublicKey(conn io.Writer, publicKey []byte) error {
	// Envoyer la taille
	size := uint32(len(publicKey))
	if err := binary.Write(conn, binary.BigEndian, size); err != nil {
		return err
	}

	// Envoyer les données
	_, err := conn.Write(publicKey)
	return err
}

// receivePublicKey reçoit une clé publique de la connexion
func (kke *KyberKeyExchange) receivePublicKey(conn io.Reader) ([]byte, error) {
	// Recevoir la taille
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	// Vérifier la taille
	if size != kyber768.PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	// Recevoir les données
	publicKey := make([]byte, size)
	_, err := io.ReadFull(conn, publicKey)
	return publicKey, err
}

// sendCiphertext envoie un ciphertext sur la connexion
func (kke *KyberKeyExchange) sendCiphertext(conn io.Writer, ciphertext []byte) error {
	// Envoyer la taille
	size := uint32(len(ciphertext))
	if err := binary.Write(conn, binary.BigEndian, size); err != nil {
		return err
	}

	// Envoyer les données
	_, err := conn.Write(ciphertext)
	return err
}

// receiveCiphertext reçoit un ciphertext de la connexion
func (kke *KyberKeyExchange) receiveCiphertext(conn io.Reader) ([]byte, error) {
	// Recevoir la taille
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}

	// Vérifier la taille (doit être la taille du ciphertext Kyber)
	if size > kyber768.CiphertextSize*2 { // Marge de sécurité
		return nil, ErrInvalidKeySize
	}

	// Recevoir les données
	ciphertext := make([]byte, size)
	_, err := io.ReadFull(conn, ciphertext)
	return ciphertext, err
}

// GetKeyExchangeOverhead retourne la taille des données échangées
func (kke *KyberKeyExchange) GetKeyExchangeOverhead() map[string]int {
	return map[string]int{
		"public_key_size": kyber768.PublicKeySize,
		"ciphertext_size": kyber768.CiphertextSize,
		"shared_key_size": kyber768.SharedKeySize,
		"total_exchange":  kyber768.PublicKeySize + kyber768.CiphertextSize + 8, // +8 pour les headers de taille
	}
}
