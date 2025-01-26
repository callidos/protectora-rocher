package tests

import (
	"bytes"
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

// TestFullKyberExchange performs a full client-server key exchange simulation
func TestFullKyberExchange(t *testing.T) {
	log.Println("[DEBUG] Début du test d'échange de clé Kyber-Dilithium")

	serverPubKey, serverPrivKey, err := communication.GenerateDilithiumKeyPair()
	if err != nil {
		t.Fatalf("[ERROR] Échec de la génération des clés Dilithium du serveur: %v", err)
	}
	log.Println("[DEBUG] Clés Dilithium du serveur générées avec succès")

	serverConn, clientConn := net.Pipe()
	log.Println("[DEBUG] Connexion simulée entre le serveur et le client établie")

	// Lancer l'échange de clés sécurisé côté serveur
	resultChan, err := communication.PerformAuthenticatedKeyExchange(serverConn, serverPrivKey)
	if err != nil {
		t.Fatalf("[ERROR] Erreur lors de la configuration du serveur: %v", err)
	}
	log.Println("[DEBUG] Échange de clé sécurisé côté serveur lancé avec succès")

	// Simuler la logique côté client
	clientSharedKey, clientErr := simulateClient(clientConn, serverPubKey)
	if clientErr != nil {
		t.Fatalf("[ERROR] Erreur côté client: %v", clientErr)
	}
	log.Println("[DEBUG] Échange de clé côté client terminé avec succès")
	clientConn.Close()

	// Récupérer le résultat de l'échange côté serveur
	result := <-resultChan
	if result.Err != nil {
		t.Fatalf("[ERROR] Erreur côté serveur: %v", result.Err)
	}
	log.Println("[DEBUG] Résultat de l'échange de clé reçu côté serveur")

	log.Printf("[DEBUG] Clé partagée côté serveur : %x", result.Key[:])
	log.Printf("[DEBUG] Clé partagée côté client : %x", clientSharedKey)

	// Vérification si les clés partagées sont identiques
	if !bytes.Equal(result.Key[:], clientSharedKey) {
		t.Fatalf("[ERROR] Les clés partagées ne correspondent pas.\nServeur: %x\nClient: %x", result.Key[:], clientSharedKey)
	}

	log.Println("[DEBUG] Échange de clé Kyber-Dilithium réussi")
}

// simulateClient handles the client-side logic of the Kyber exchange
func simulateClient(conn net.Conn, serverPubDilithium *mode2.PublicKey) ([]byte, error) {
	log.Println("[DEBUG] Début de la simulation client")

	pkBytes, err := readBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la lecture de la clé publique Kyber: %v", err)
		return nil, fmt.Errorf("échec de la lecture de la clé publique Kyber : %v", err)
	}

	log.Printf("[DEBUG] Clé publique Kyber reçue : %x", pkBytes)

	signature, err := readBytesWithLength(conn)
	if err != nil {
		log.Printf("[ERROR] Échec de la lecture de la signature Dilithium: %v", err)
		return nil, fmt.Errorf("échec de la lecture de la signature Dilithium : %v", err)
	}

	log.Printf("[DEBUG] Signature Dilithium reçue : %x", signature)

	log.Println("[DEBUG] Vérification de la signature côté client")
	if !mode2.Verify(serverPubDilithium, pkBytes, signature) {
		log.Println("[ERROR] Signature Dilithium invalide côté client")
		return nil, fmt.Errorf("signature Dilithium invalide")
	}

	log.Println("[DEBUG] Signature Dilithium validée côté client")

	var pkServer kyber768.PublicKey
	pkServer.Unpack(pkBytes)

	log.Println("[DEBUG] Clé publique Kyber désérialisée")

	ct := make([]byte, kyber768.CiphertextSize)
	sharedKey := make([]byte, kyber768.SharedKeySize)
	pkServer.EncapsulateTo(ct, sharedKey, nil)

	log.Printf("[DEBUG] Secret partagé dérivé côté client : %x", sharedKey)

	if err := writeBytesWithLength(conn, ct); err != nil {
		log.Printf("[ERROR] Échec de l'envoi du ciphertext Kyber: %v", err)
		return nil, fmt.Errorf("échec de l'envoi du ciphertext Kyber : %v", err)
	}

	log.Println("[INFO] Simulation client terminée avec succès")
	return sharedKey, nil
}

// readBytesWithLength lit les données avec un préfixe de longueur à partir de la connexion
func readBytesWithLength(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("échec de lecture de la longueur des données : %v", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > maxDataSize {
		return nil, fmt.Errorf("taille des données trop volumineuse")
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("échec de lecture des données : %v", err)
	}
	return data, nil
}

func writeBytesWithLength(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	if length > maxDataSize {
		return fmt.Errorf("taille des données trop volumineuse")
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)

	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("échec d'envoi de la longueur des données : %v", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("échec d'envoi des données : %v", err)
	}
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
