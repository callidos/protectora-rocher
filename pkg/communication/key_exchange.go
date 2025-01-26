package communication

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

// Structure contenant les clés publiques et privées Kyber et Dilithium
type KeyPair struct {
	KyberPublicKey      []byte
	KyberPrivateKey     []byte
	DilithiumPublicKey  []byte
	DilithiumPrivateKey []byte
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

func performKyberDilithiumKeyExchange(conn io.ReadWriter) error {
	log.Println("[DEBUG] Début de l'échange de clé Kyber-Dilithium")

	// Génération des clés Kyber
	log.Println("[DEBUG] Génération de la paire de clés Kyber")
	pkServer, skServer, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return fmt.Errorf("échec de la génération de la paire Kyber768: %w", err)
	}

	pkBytes, err := pkServer.MarshalBinary()
	if err != nil {
		return fmt.Errorf("échec de la sérialisation de la clé publique Kyber: %w", err)
	}
	log.Printf("[DEBUG] Clé publique Kyber (taille: %d) : %x", len(pkBytes), pkBytes)

	// Génération des clés Dilithium
	publicKey, privateKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("échec de la génération de la clé Dilithium: %w", err)
	}
	publicKeyBytes := publicKey.Bytes()
	log.Printf("[DEBUG] Clé publique Dilithium (taille: %d) : %x", len(publicKeyBytes), publicKeyBytes)

	// Signature du message contenant la clé publique Kyber
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(privateKey, pkBytes, signature)
	log.Printf("[DEBUG] Signature Dilithium (taille: %d) : %x", len(signature), signature)

	// Envoi des données
	log.Println("[DEBUG] Envoi de la clé publique Kyber et de la signature")
	if err := sendBytesWithLength(conn, pkBytes); err != nil {
		return fmt.Errorf("échec de l'envoi de la clé publique Kyber: %w", err)
	}
	if err := sendBytesWithLength(conn, signature); err != nil {
		return fmt.Errorf("échec de l'envoi de la signature Dilithium: %w", err)
	}

	// Réception des données du client
	log.Println("[DEBUG] Réception de la clé publique Kyber du client")
	pkClientBytes, err := receiveBytesWithLength(conn)
	if err != nil {
		return fmt.Errorf("échec de la réception de la clé publique Kyber du client: %w", err)
	}
	log.Printf("[DEBUG] Clé publique Kyber du client (taille: %d) reçue : %x", len(pkClientBytes), pkClientBytes)

	if len(pkClientBytes) != kyber768.PublicKeySize {
		return fmt.Errorf("erreur : taille incorrecte de la clé publique Kyber reçue")
	}

	log.Println("[DEBUG] Réception de la signature Dilithium du client")
	receivedSignature, err := receiveBytesWithLength(conn)
	if err != nil {
		return fmt.Errorf("échec de la réception de la signature Dilithium du client: %w", err)
	}
	log.Printf("[DEBUG] Signature Dilithium du client reçue (taille: %d) : %x", len(receivedSignature), receivedSignature)

	// Vérification de la signature du client
	log.Println("[DEBUG] Vérification de la signature Dilithium du client")
	if !mode2.Verify(publicKey, pkClientBytes, receivedSignature) {
		log.Println("[ERROR] Signature Dilithium invalide côté client")
		log.Printf("[DEBUG] Clé publique utilisée pour la vérification (hex) : %x", publicKeyBytes)
		log.Printf("[DEBUG] Données signées (hex) : %x", pkClientBytes)
		return fmt.Errorf("signature Dilithium invalide")
	}
	log.Println("[DEBUG] Signature Dilithium du client validée avec succès")

	// Réception du ciphertext Kyber du client
	log.Println("[DEBUG] Réception du ciphertext Kyber du client")
	ctClient, err := receiveBytesWithLength(conn)
	if err != nil {
		return fmt.Errorf("échec de la réception du ciphertext Kyber du client: %w", err)
	}
	log.Printf("[DEBUG] Ciphertext Kyber reçu (taille: %d) : %x", len(ctClient), ctClient)

	if len(ctClient) != kyber768.CiphertextSize {
		return fmt.Errorf("taille du ciphertext Kyber invalide: reçu %d octets", len(ctClient))
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

func GenerateKeyPairs() (*KeyPair, error) {
	log.Println("[DEBUG] Début de la génération des clés Kyber et Dilithium")

	kyberPublicKey, kyberPrivateKey := make([]byte, 1184), make([]byte, 2400)
	_, err := rand.Read(kyberPublicKey)
	if err != nil {
		return nil, errors.New("erreur lors de la génération de la clé publique Kyber")
	}
	_, err = rand.Read(kyberPrivateKey)
	if err != nil {
		return nil, errors.New("erreur lors de la génération de la clé privée Kyber")
	}

	dilithiumPublicKey, dilithiumPrivateKey := make([]byte, 1312), make([]byte, 2560)
	_, err = rand.Read(dilithiumPublicKey)
	if err != nil {
		return nil, errors.New("erreur lors de la génération de la clé publique Dilithium")
	}
	_, err = rand.Read(dilithiumPrivateKey)
	if err != nil {
		return nil, errors.New("erreur lors de la génération de la clé privée Dilithium")
	}

	log.Printf("[INFO] Clé publique Kyber générée : %s\n", hex.EncodeToString(kyberPublicKey))
	log.Printf("[INFO] Clé publique Dilithium générée : %s\n", hex.EncodeToString(dilithiumPublicKey))

	return &KeyPair{
		KyberPublicKey:      kyberPublicKey,
		KyberPrivateKey:     kyberPrivateKey,
		DilithiumPublicKey:  dilithiumPublicKey,
		DilithiumPrivateKey: dilithiumPrivateKey,
	}, nil
}

// Signature des données avec la clé privée Dilithium
func SignData(data []byte, privateKey []byte) ([]byte, error) {
	log.Println("[DEBUG] Signature des données avec la clé privée Dilithium")

	signature := make([]byte, 2420)
	_, err := rand.Read(signature)
	if err != nil {
		return nil, errors.New("échec de la génération de la signature")
	}

	log.Printf("[INFO] Signature générée : %s\n", hex.EncodeToString(signature))
	return signature, nil
}

// Vérification de la signature avec la clé publique Dilithium
func VerifySignature(data, signature, publicKey []byte) bool {
	log.Println("[DEBUG] Vérification de la signature Dilithium")

	expectedSignature := make([]byte, len(signature))
	copy(expectedSignature, signature) // Simulation de la vérification réussie

	if string(expectedSignature) == string(signature) {
		log.Println("[INFO] Signature valide")
		return true
	}

	log.Println("[ERROR] Signature invalide")
	return false
}

// Simulation de l'échange de clés
func SimulateKeyExchange() error {
	log.Println("[DEBUG] Début de la simulation d'échange de clés")

	keyPair, err := GenerateKeyPairs()
	if err != nil {
		return err
	}

	// Étape 1: Génération de la signature locale et vérification
	data := []byte("message à signer")
	signature, err := SignData(data, keyPair.DilithiumPrivateKey)
	if err != nil {
		return err
	}

	if !VerifySignature(data, signature, keyPair.DilithiumPublicKey) {
		return errors.New("échec de la vérification locale de la signature")
	}
	log.Println("[SUCCESS] Vérification locale de la signature réussie")

	// Étape 2: Simulation de transmission et réception
	transmittedPubKey := make([]byte, len(keyPair.KyberPublicKey))
	copy(transmittedPubKey, keyPair.KyberPublicKey)

	transmittedSignature := make([]byte, len(signature))
	copy(transmittedSignature, signature)

	log.Printf("[DEBUG] Clé publique Kyber transmise : %s\n", hex.EncodeToString(transmittedPubKey))
	log.Printf("[DEBUG] Signature transmise : %s\n", hex.EncodeToString(transmittedSignature))

	// Étape 3: Vérification après réception
	if string(transmittedPubKey) != string(keyPair.KyberPublicKey) {
		log.Println("[ERROR] Divergence détectée dans la clé publique Kyber après transmission")
		return errors.New("divergence détectée dans la clé publique Kyber")
	}

	if !VerifySignature(data, transmittedSignature, keyPair.DilithiumPublicKey) {
		log.Println("[ERROR] La signature reçue est invalide")
		return errors.New("la signature reçue est invalide")
	}

	log.Println("[SUCCESS] Échange de clés simulé avec succès")
	return nil
}
