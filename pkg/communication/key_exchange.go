package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

const keyRotationInterval = 10 * time.Minute
const maxDataSize = 65536

var (
	mutex       sync.Mutex
	currentKey  [32]byte
	lastKeyTime time.Time
)

type KeyExchangeResult struct {
	Key [32]byte
	Err error
}

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func PerformAuthenticatedKeyExchange(conn io.ReadWriter, privateKey ed25519.PrivateKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		mutex.Lock()
		defer mutex.Unlock()

		if time.Since(lastKeyTime) > keyRotationInterval || currentKey == [32]byte{} {
			if err := performKyberKeyExchange(conn, privateKey); err != nil {
				resultChan <- KeyExchangeResult{Err: fmt.Errorf("échec de l'échange de clé Kyber : %w", err)}
				return
			}
			lastKeyTime = time.Now()
		}

		resultChan <- KeyExchangeResult{Key: currentKey}
	}()

	return resultChan, nil
}

func performKyberKeyExchange(conn io.ReadWriter, privateKey ed25519.PrivateKey) error {
	pkServer, skServer, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return fmt.Errorf("échec génération paire Kyber768 : %w", err)
	}

	pkBytes, err := pkServer.MarshalBinary()
	if err != nil {
		return fmt.Errorf("échec sérialisation clé publique Kyber : %w", err)
	}

	signature := ed25519.Sign(privateKey, pkBytes)

	if err := sendBytesWithLength(conn, pkBytes); err != nil {
		return fmt.Errorf("échec de l'envoi de la clé publique Kyber : %w", err)
	}
	if err := sendBytesWithLength(conn, signature); err != nil {
		return fmt.Errorf("échec de l'envoi de la signature Ed25519 : %w", err)
	}

	ctClient, err := receiveBytesWithLength(conn)
	if err != nil {
		return fmt.Errorf("erreur réception ciphertext Kyber : %w", err)
	}
	if len(ctClient) != kyber768.CiphertextSize {
		return fmt.Errorf("taille du ciphertext Kyber invalide : reçu %d octets", len(ctClient))
	}

	sharedSecret := make([]byte, kyber768.SharedKeySize)
	skServer.DecapsulateTo(sharedSecret, ctClient)

	copy(currentKey[:], sharedSecret)
	return nil
}

func sendBytesWithLength(conn io.Writer, data []byte) error {
	length := uint32(len(data))
	if length > maxDataSize {
		return fmt.Errorf("données trop volumineuses")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)

	_, err := conn.Write(append(lenBuf, data...))
	return err
}

func receiveBytesWithLength(conn io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("échec de lecture de la longueur des données : %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxDataSize {
		return nil, fmt.Errorf("données trop volumineuses")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("échec de lecture des données : %w", err)
	}
	return buf, nil
}

func ResetKeyExchangeState() {
	mutex.Lock()
	defer mutex.Unlock()
	currentKey = [32]byte{}
	lastKeyTime = time.Time{}
}
