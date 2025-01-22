package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

const (
	keyRotationInterval = 10 * time.Minute
)

var (
	mutex       sync.Mutex
	currentKey  [32]byte
	lastKeyTime time.Time
)

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur de génération Ed25519 : %v", err)
	}
	return pub, priv, nil
}

func PerformAuthenticatedKeyExchange(conn net.Conn,
	privateEd25519 ed25519.PrivateKey,
	publicEd25519 ed25519.PublicKey,
) ([32]byte, error) {

	mutex.Lock()
	defer mutex.Unlock()

	if time.Since(lastKeyTime) > keyRotationInterval || currentKey == [32]byte{} {
		if err := exchangeNewKyberSessionKey(conn, privateEd25519); err != nil {
			return [32]byte{}, fmt.Errorf("échec de l'échange de clé Kyber : %v", err)
		}
		lastKeyTime = time.Now()
	}

	return currentKey, nil
}

func exchangeNewKyberSessionKey(conn net.Conn, privateEd25519 ed25519.PrivateKey) error {

	pkServer, skServer, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return fmt.Errorf("erreur de génération de paire Kyber768 : %v", err)
	}

	pkBytes, err := pkServer.MarshalBinary()
	if err != nil {
		return fmt.Errorf("erreur de sérialisation pk Kyber : %v", err)
	}

	signature := ed25519.Sign(privateEd25519, pkBytes)

	if err := sendBytesWithLength(conn, pkBytes); err != nil {
		return fmt.Errorf("erreur lors de l'envoi de pkKyber : %v", err)
	}
	if err := sendBytesWithLength(conn, signature); err != nil {
		return fmt.Errorf("erreur lors de l'envoi de la signature Ed25519 : %v", err)
	}

	ctClient, err := receiveBytesWithLength(conn)
	if err != nil {
		return fmt.Errorf("erreur de réception du ciphertext Kyber : %v", err)
	}
	if len(ctClient) != kyber768.CiphertextSize {
		return fmt.Errorf("taille invalide de ciphertext Kyber, reçu %d octets", len(ctClient))
	}

	sharedSecret := make([]byte, kyber768.SharedKeySize)
	skServer.DecapsulateTo(sharedSecret, ctClient)

	copy(currentKey[:], sharedSecret)

	return nil
}

func sendBytesWithLength(conn net.Conn, data []byte) error {
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(data)))

	if _, err := conn.Write(lengthBytes[:]); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

func receiveBytesWithLength(conn net.Conn) ([]byte, error) {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func ResetKeyExchangeState() {
	mutex.Lock()
	defer mutex.Unlock()
	currentKey = [32]byte{}
	lastKeyTime = time.Time{}
}
