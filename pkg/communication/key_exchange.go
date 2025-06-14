package communication

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
)

const (
	maxDataSize = 65536
)

// KeyExchangeResult contient le résultat de l'échange de clés.
type KeyExchangeResult struct {
	Key [32]byte
	Err error
}

// ClientPerformKeyExchange effectue la partie handshake côté client (initiateur).
func ClientPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, serverPubKey ed25519.PublicKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		// Générer une paire de clés Kyber pour l'échange
		publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("keygen failed: %w", err)}
			return
		}

		publicKeyBytes := make([]byte, kyber768.PublicKeySize)
		publicKey.Pack(publicKeyBytes)

		// Signer la clé publique Kyber avec notre clé privée Ed25519
		signature := ed25519.Sign(privKey, publicKeyBytes)

		// Envoyer notre clé publique Kyber + signature
		if err := sendData(conn, publicKeyBytes, signature); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("send failed: %w", err)}
			return
		}

		// Recevoir le ciphertext du serveur
		ciphertext, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("receive ciphertext failed: %w", err)}
			return
		}

		// Recevoir la signature du serveur
		serverSignature, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("receive server signature failed: %w", err)}
			return
		}

		// CORRECTION: Vérifier la signature du serveur sur le ciphertext
		if !ed25519.Verify(serverPubKey, ciphertext, serverSignature) {
			resultChan <- KeyExchangeResult{Err: errors.New("server signature verification failed")}
			return
		}

		// Vérifier la taille du ciphertext
		if len(ciphertext) != kyber768.CiphertextSize {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("invalid ciphertext length: got %d, expected %d", len(ciphertext), kyber768.CiphertextSize)}
			return
		}

		// Décapsuler pour obtenir le secret partagé
		sharedSecret := make([]byte, kyber768.SharedKeySize)
		privateKey.DecapsulateTo(sharedSecret, ciphertext)

		// Dériver la clé de session
		sessionKey := DeriveSessionKey(sharedSecret)
		Memzero(sharedSecret)

		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

// ServerPerformKeyExchange effectue la partie handshake côté serveur.
func ServerPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey, clientPubKey ed25519.PublicKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		// Recevoir la clé publique Kyber du client
		clientPubKeyBytes, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to read client public key: %w", err)}
			return
		}

		// Recevoir la signature du client
		clientSignature, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to read client signature: %w", err)}
			return
		}

		// CORRECTION: Vérifier la signature du client sur sa clé publique Kyber
		if !ed25519.Verify(clientPubKey, clientPubKeyBytes, clientSignature) {
			resultChan <- KeyExchangeResult{Err: errors.New("client signature verification failed")}
			return
		}

		// Décoder la clé publique Kyber du client
		clientKyberPubKey, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientPubKeyBytes)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to unpack client public key: %w", err)}
			return
		}

		// Encapsuler pour créer le ciphertext et le secret partagé
		ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(clientKyberPubKey)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("encapsulation failed: %w", err)}
			return
		}

		// Signer le ciphertext avec notre clé privée Ed25519
		serverSignature := ed25519.Sign(privKey, ciphertext)

		// Envoyer le ciphertext + notre signature
		if err := sendData(conn, ciphertext, serverSignature); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to send ciphertext and signature: %w", err)}
			return
		}

		// Dériver la clé de session
		sessionKey := DeriveSessionKey(sharedSecret)
		Memzero(sharedSecret)

		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

func sendBytes(conn io.Writer, data []byte) error {
	if len(data) > maxDataSize {
		return fmt.Errorf("données trop volumineuses")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func sendData(conn io.Writer, data1, data2 []byte) error {
	if err := sendBytes(conn, data1); err != nil {
		return err
	}
	return sendBytes(conn, data2)
}

func receiveBytes(conn io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("échec lecture longueur: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxDataSize {
		return nil, fmt.Errorf("données trop volumineuses")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("échec lecture données: %w", err)
	}
	return buf, nil
}

func DeriveSessionKey(sharedSecret []byte) [32]byte {
	h := hkdf.New(sha256.New, sharedSecret, nil, []byte("protectora-rocher-session-v1"))
	key := [32]byte{}
	_, _ = io.ReadFull(h, key[:])
	return key
}

func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
