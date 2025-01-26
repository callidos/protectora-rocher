package communication

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
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

// GenerateDilithiumKeyPair génère une paire de clés publique/privée Dilithium.
func GenerateDilithiumKeyPair() (*mode2.PublicKey, *mode2.PrivateKey, error) {
	pk, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("erreur de génération de clés: %w", err)
	}
	return pk, sk, nil
}

// SignMessage Dilithium signe un message avec la clé privée.
func SignMessage(privateKey *mode2.PrivateKey, message []byte) ([]byte, error) {
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(privateKey, message, signature)
	return signature, nil
}

// VerifySignature Dilithium vérifie une signature pour un message donné.
func VerifySignature(publicKey *mode2.PublicKey, message []byte, signature []byte) bool {
	return mode2.Verify(publicKey, message, signature)
}

func PerformAuthenticatedKeyExchange(conn io.ReadWriter, privateKey *mode2.PrivateKey) (<-chan KeyExchangeResult, error) {
	resultChan := make(chan KeyExchangeResult, 1)

	go func() {
		defer close(resultChan)

		mutex.Lock()
		defer mutex.Unlock()

		if time.Since(lastKeyTime) > keyRotationInterval || currentKey == [32]byte{} {
			if err := performKyberDilithiumKeyExchange(conn); err != nil {
				resultChan <- KeyExchangeResult{Err: fmt.Errorf("échec de l'échange de clé Kyber-Dilithium : %w", err)}
				return
			}
			lastKeyTime = time.Now()
		}

		resultChan <- KeyExchangeResult{Key: currentKey}
	}()

	return resultChan, nil
}

func performKyberDilithiumKeyExchange(conn io.ReadWriter) error {
	log.Println("[DEBUG] Début de l'échange de clé Kyber-Dilithium")

	// Génération des clés Kyber
	log.Println("[DEBUG] Génération de la paire de clés Kyber")
	pkServer, skServer, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		log.Printf("[ERROR] Échec de la génération de la paire Kyber768: %v", err)
		return fmt.Errorf("échec de la génération de la paire Kyber768 : %w", err)
	}

	pkBytes, err := pkServer.MarshalBinary()
	if err != nil {
		log.Printf("[ERROR] Échec de la sérialisation de la clé publique Kyber: %v", err)
		return fmt.Errorf("échec de la sérialisation de la clé publique Kyber : %w", err)
	}
	log.Printf("[DEBUG] Clé publique Kyber générée et sérialisée : %x", pkBytes)

	// Génération des clés Dilithium
	log.Println("[DEBUG] Génération de la paire de clés Dilithium")
	publicKey, privateKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("[ERROR] Échec de la génération de la clé Dilithium: %v", err)
		return fmt.Errorf("échec de la génération de la clé Dilithium : %w", err)
	}
	log.Printf("[DEBUG] Clé publique Dilithium générée (hex) : %x", publicKey.Bytes())

	// Signature du message contenant la clé publique Kyber
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(privateKey, pkBytes, signature)
	log.Printf("[DEBUG] Signature Dilithium générée (hex) : %x", signature)

	// Envoi de la clé publique Kyber et de la signature Dilithium
	log.Println("[DEBUG] Envoi de la clé publique Kyber")
	if err := sendBytesWithLength(conn, pkBytes); err != nil {
		log.Printf("[ERROR] Échec de l'envoi de la clé publique Kyber: %v", err)
		return fmt.Errorf("échec de l'envoi de la clé publique Kyber : %w", err)
	}

	log.Println("[DEBUG] Envoi de la signature Dilithium")
	if err := sendBytesWithLength(conn, signature); err != nil {
		log.Printf("[ERROR] Échec de l'envoi de la signature Dilithium: %v", err)
		return fmt.Errorf("échec de l'envoi de la signature Dilithium : %w", err)
	}

	// Réception de la clé publique Kyber du client
	log.Println("[DEBUG] Réception de la clé publique Kyber du client")
	pkClientBytes, err := receiveBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la réception de la clé publique Kyber du client: %v", err)
		return fmt.Errorf("échec de la réception de la clé publique Kyber du client : %w", err)
	}
	log.Printf("[DEBUG] Clé publique Kyber du client reçue (hex) : %x", pkClientBytes)

	// Réception de la signature Dilithium du client
	log.Println("[DEBUG] Réception de la signature Dilithium du client")
	receivedSignature, err := receiveBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la réception de la signature Dilithium du client: %v", err)
		return fmt.Errorf("échec de la réception de la signature Dilithium du client : %w", err)
	}
	log.Printf("[DEBUG] Signature Dilithium du client reçue (hex) : %x", receivedSignature)

	// Vérification de la signature du client
	log.Println("[DEBUG] Vérification de la signature Dilithium du client")
	if !mode2.Verify(publicKey, pkClientBytes, receivedSignature) {
		log.Println("[ERROR] Échec de la vérification de la signature Dilithium du client")
		return fmt.Errorf("échec de la vérification de la signature Dilithium du client")
	}
	log.Println("[DEBUG] Signature Dilithium du client validée avec succès")

	// Réception du ciphertext Kyber du client
	log.Println("[DEBUG] Réception du ciphertext Kyber du client")
	ctClient, err := receiveBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Erreur de réception du ciphertext Kyber du client: %v", err)
		return fmt.Errorf("erreur de réception du ciphertext Kyber du client : %w", err)
	}
	log.Printf("[DEBUG] Ciphertext Kyber du client reçu (hex) : %x", ctClient)

	if len(ctClient) != kyber768.CiphertextSize {
		log.Printf("[ERROR] Taille du ciphertext Kyber invalide: reçu %d octets", len(ctClient))
		return fmt.Errorf("taille du ciphertext Kyber invalide : reçu %d octets", len(ctClient))
	}

	// Décapsulation du secret partagé
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	skServer.DecapsulateTo(sharedSecret, ctClient)
	log.Printf("[DEBUG] Secret partagé dérivé côté serveur (hex) : %x", sharedSecret)

	// Stockage de la clé partagée pour utilisation future
	mutex.Lock()
	copy(currentKey[:], sharedSecret)
	lastKeyTime = time.Now()
	mutex.Unlock()

	log.Println("[INFO] Échange de clé Kyber-Dilithium terminé avec succès")
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
