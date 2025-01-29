package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

const (
	maxDataSize = 65536
)

var (
	mutex sync.Mutex
)

type KeyExchangeResult struct {
	Key [32]byte
	Err error
}

func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func PerformAuthenticatedKeyExchange(conn io.ReadWriter, privKey []byte) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		pk, sk, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("keygen failed: %w", err)}
			return
		}

		pkBytes, _ := pk.MarshalBinary()
		signature := ed25519.Sign(ed25519.PrivateKey(privKey), pkBytes)

		// Envoi clé publique + signature
		if err := sendData(conn, pkBytes, signature); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("send failed: %w", err)}
			return
		}

		// Réception ciphertext client
		ct, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("receive failed: %w", err)}
			return
		}

		// Dérivation clé de session
		sharedSecret := make([]byte, kyber768.SharedKeySize)
		sk.DecapsulateTo(sharedSecret, ct)

		sessionKey := [32]byte{}
		copy(sessionKey[:], sharedSecret[:32])

		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

func sendData(conn io.Writer, pkBytes, signature []byte) error {
	if err := sendBytes(conn, pkBytes); err != nil {
		return err
	}
	return sendBytes(conn, signature)
}

func sendBytes(conn io.Writer, data []byte) error {
	if len(data) > maxDataSize {
		return fmt.Errorf("données trop volumineuses")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	_, err := conn.Write(append(lenBuf, data...))
	return err
}

func receiveBytes(conn io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("échec lecture longueur données : %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxDataSize {
		return nil, fmt.Errorf("données trop volumineuses")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("échec lecture données : %w", err)
	}
	return buf, nil
}

func ResetKeyExchangeState() {
	mutex.Lock()
	defer mutex.Unlock()
}
