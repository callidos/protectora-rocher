package tests

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"protectora-rocher/pkg/communication"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

const maxDataSize = 65536

// simulateClient handles the client-side logic of the Kyber exchange
func simulateClient(conn net.Conn, serverPubDilithium *mode2.PublicKey) ([]byte, error) {
	log.Println("[DEBUG] Début de la simulation client")

	pkBytes, err := readBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la lecture de la clé publique Kyber: %v", err)
		return nil, fmt.Errorf("échec de la lecture de la clé publique Kyber : %v", err)
	}
	log.Printf("[DEBUG] Clé publique Kyber reçue : %x (taille : %d octets)", pkBytes, len(pkBytes))

	signature, err := readBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la lecture de la signature Dilithium: %v", err)
		return nil, fmt.Errorf("échec de la lecture de la signature Dilithium : %v", err)
	}
	log.Printf("[DEBUG] Signature Dilithium reçue : %x (taille : %d octets)", signature, len(signature))

	// Vérification de la signature
	log.Println("[DEBUG] Vérification de la signature Dilithium côté client")
	if !mode2.Verify(serverPubDilithium, pkBytes, signature) {
		log.Println("[ERROR] Signature Dilithium invalide côté client")
		return nil, fmt.Errorf("signature Dilithium invalide")
	}
	log.Println("[DEBUG] Signature Dilithium validée côté client")

	// Désérialisation de la clé publique Kyber
	log.Println("[DEBUG] Désérialisation de la clé publique Kyber reçue")
	if len(pkBytes) != kyber768.PublicKeySize {
		log.Printf("[ERROR] Taille incorrecte de la clé publique Kyber reçue : attendu %d, reçu %d", kyber768.PublicKeySize, len(pkBytes))
		return nil, fmt.Errorf("taille incorrecte de la clé publique Kyber reçue")
	}

	var pkServer kyber768.PublicKey
	pkServer.Unpack(pkBytes)
	log.Println("[DEBUG] Clé publique Kyber désérialisée avec succès")

	// Encapsulation côté client
	log.Println("[DEBUG] Encapsulation du secret partagé à l'aide de la clé publique Kyber")
	ct := make([]byte, kyber768.CiphertextSize)
	sharedKey := make([]byte, kyber768.SharedKeySize)

	pkServer.EncapsulateTo(ct, sharedKey, nil)
	log.Printf("[DEBUG] Secret partagé dérivé côté client : %x", sharedKey)

	// Envoi du ciphertext Kyber au serveur
	log.Println("[DEBUG] Envoi du ciphertext Kyber au serveur")
	if err := writeBytesWithLength(conn, ct); err != nil {
		log.Printf("[ERROR] Échec de l'envoi du ciphertext Kyber: %v", err)
		return nil, fmt.Errorf("échec de l'envoi du ciphertext Kyber : %v", err)
	}
	log.Println("[DEBUG] Ciphertext Kyber envoyé avec succès")

	log.Println("[INFO] Simulation client terminée avec succès")
	return sharedKey, nil
}

// readBytesWithLength lit les données avec un préfixe de longueur à partir de la connexion
func readBytesWithLength(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("[ERROR] Échec de lecture de la longueur des données : %v", err)
		return nil, fmt.Errorf("échec de lecture de la longueur des données : %v", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)
	log.Printf("[DEBUG] Longueur des données à lire : %d bytes", length)

	if length > maxDataSize {
		log.Printf("[ERROR] Taille des données trop volumineuse : %d bytes", length)
		return nil, fmt.Errorf("taille des données trop volumineuse")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		log.Printf("[ERROR] Échec de lecture des données : %v", err)
		return nil, fmt.Errorf("échec de lecture des données : %v", err)
	}
	log.Printf("[DEBUG] Données reçues (hex) : %x", data)
	return data, nil
}

func writeBytesWithLength(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	log.Printf("[DEBUG] Longueur des données à envoyer : %d bytes", length)

	if length > maxDataSize {
		log.Printf("[ERROR] Taille des données trop volumineuse : %d bytes", length)
		return fmt.Errorf("taille des données trop volumineuse")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)

	if _, err := conn.Write(lenBuf); err != nil {
		log.Printf("[ERROR] Échec d'envoi de la longueur des données : %v", err)
		return fmt.Errorf("échec d'envoi de la longueur des données : %v", err)
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("[ERROR] Échec d'envoi des données : %v", err)
		return fmt.Errorf("échec d'envoi des données : %v", err)
	}

	log.Printf("[DEBUG] Données envoyées (hex) : %x", data)
	return nil
}

func testDilithiumSignature() {
	message := []byte("Test message")
	pk, sk, _ := mode2.GenerateKey(rand.Reader)
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(sk, message, signature)

	if mode2.Verify(pk, message, signature) {
		log.Println("[SUCCESS] Signature validée avec succès.")
	} else {
		log.Println("[ERROR] Signature invalide.")
	}
}

func TestFullKyberExchange(t *testing.T) {
	err := communication.SimulateKeyExchange()
	if err != nil {
		t.Errorf("Test échoué : %v", err)
	} else {
		t.Logf("[SUCCESS] Échange de clés réussi")
	}
}

func TestLocalSignatureVerification(t *testing.T) {
	keyPair, _ := communication.GenerateKeyPairs()
	data := []byte("message test")

	signature, err := communication.SignData(data, keyPair.DilithiumPrivateKey)
	if err != nil {
		t.Errorf("Échec de la signature : %v", err)
	}

	if !communication.VerifySignature(data, signature, keyPair.DilithiumPublicKey) {
		t.Errorf("La signature locale est invalide")
	} else {
		t.Log("[SUCCESS] Test local: la signature est valide.")
	}
}
