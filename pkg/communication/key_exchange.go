package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
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

func PerformAuthenticatedKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("keygen failed: %w", err)}
			return
		}

		publicKeyBytes := make([]byte, kyber768.PublicKeySize)
		publicKey.Pack(publicKeyBytes)

		signature := ed25519.Sign(privKey, publicKeyBytes)

		if err := sendData(conn, publicKeyBytes, signature); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("send failed: %w", err)}
			return
		}

		ciphertext, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("receive failed: %w", err)}
			return
		}

		sharedSecret := make([]byte, kyber768.SharedKeySize)
		privateKey.DecapsulateTo(sharedSecret, ciphertext)

		sessionKey := DeriveSessionKey(sharedSecret)
		Memzero(sharedSecret)

		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

func DeriveSessionKey(sharedSecret []byte) [32]byte {
	h := hkdf.New(sha256.New, sharedSecret, nil, nil)
	key := [32]byte{}
	io.ReadFull(h, key[:])
	return key
}

func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

func receivePeerData(conn io.Reader) ([]byte, []byte, error) {
	pkBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, nil, err
	}

	sigBytes, err := receiveBytes(conn)
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, sigBytes, nil
}

func verifyPeerSignature(pubKey ed25519.PublicKey, sig, data []byte) error {
	if !ed25519.Verify(pubKey, data, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ResetKeyExchangeState() {
	mutex.Lock()
	defer mutex.Unlock()
}
