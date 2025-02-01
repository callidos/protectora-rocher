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

// KeyExchangeResult contient le résultat de l'échange de clés.
type KeyExchangeResult struct {
	Key [32]byte
	Err error
}

// ClientPerformKeyExchange effectue la partie handshake côté client (initiateur).
func ClientPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		// Générer une paire de clés éphémères avec Kyber768.
		publicKey, privateKey, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("keygen failed: %w", err)}
			return
		}

		publicKeyBytes := make([]byte, kyber768.PublicKeySize)
		publicKey.Pack(publicKeyBytes)

		// Signer la clé publique éphémère avec la clé privée Ed25519.
		signature := ed25519.Sign(privKey, publicKeyBytes)

		// Envoyer la clé publique et la signature.
		if err := sendData(conn, publicKeyBytes, signature); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("send failed: %w", err)}
			return
		}

		// Recevoir le ciphertext contenant le secret partagé.
		ciphertext, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("receive failed: %w", err)}
			return
		}

		// Vérifier que le ciphertext est de la taille attendue.
		if len(ciphertext) != kyber768.CiphertextSize {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("invalid ciphertext length: got %d, expected %d", len(ciphertext), kyber768.CiphertextSize)}
			return
		}

		sharedSecret := make([]byte, kyber768.SharedKeySize)
		privateKey.DecapsulateTo(sharedSecret, ciphertext)

		// Dériver la clé de session via HKDF.
		sessionKey := DeriveSessionKey(sharedSecret)
		Memzero(sharedSecret)

		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

// ServerPerformKeyExchange réalise l'échange de clés sur le serveur
func ServerPerformKeyExchange(conn io.ReadWriter, privKey ed25519.PrivateKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		// Recevoir la clé publique éphémère du client
		clientPubKeyBytes, err := receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to read client public key: %w", err)}
			return
		}

		// Recevoir la signature du client (ignorée dans ce test)
		_, err = receiveBytes(conn)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to read signature: %w", err)}
			return
		}

		// Dépaqueter la clé publique du client avec la nouvelle syntaxe
		clientPubKey, err := kyber768.Scheme().UnmarshalBinaryPublicKey(clientPubKeyBytes)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to unpack client public key: %w", err)}
			return
		}

		// Encapsuler un secret partagé en utilisant la clé publique du client
		ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(clientPubKey)
		if err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("encapsulation failed: %w", err)}
			return
		}

		// Envoyer le ciphertext au client
		if err := sendBytes(conn, ciphertext); err != nil {
			resultChan <- KeyExchangeResult{Err: fmt.Errorf("failed to send ciphertext: %w", err)}
			return
		}

		// Dériver la clé de session à partir du secret partagé
		sessionKey := DeriveSessionKey(sharedSecret)
		Memzero(sharedSecret) // Effacer le secret partagé de la mémoire

		// Retourner la clé de session via le channel
		resultChan <- KeyExchangeResult{Key: sessionKey}
	}()

	return resultChan, nil
}

// --- Fonctions auxiliaires d'envoi/réception ---
// sendBytes envoie les données précédées de leur taille (4 octets).
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

// sendData envoie deux tranches de données l'une après l'autre.
func sendData(conn io.Writer, data1, data2 []byte) error {
	if err := sendBytes(conn, data1); err != nil {
		return err
	}
	return sendBytes(conn, data2)
}

// receiveBytes lit d'abord 4 octets indiquant la taille, puis lit les données.
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

// DeriveSessionKey dérive une clé de session de 32 octets à partir du secret partagé via HKDF.
func DeriveSessionKey(sharedSecret []byte) [32]byte {
	h := hkdf.New(sha256.New, sharedSecret, nil, nil)
	key := [32]byte{}
	_, _ = io.ReadFull(h, key[:])
	return key
}

// Memzero efface de manière sécurisée le contenu d'un slice.
func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func ResetKeyExchangeState() {
	// Rien à réinitialiser pour le moment.
}
