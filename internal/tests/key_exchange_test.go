package tests

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net"
	"protectora-rocher/pkg/communication"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestGenerateEd25519KeyPair et TestKeyRotation peuvent rester comme avant.
// Ci-dessous, un test plus complet qui simule vraiment un client et un serveur.
func TestFullKyberExchange(t *testing.T) {
	serverPubEd25519, serverPrivEd25519, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Impossible de générer les clés Ed25519 du serveur: %v", err)
	}

	serverConn, clientConn := net.Pipe()

	resultChan, err := communication.PerformAuthenticatedKeyExchange(
		serverConn,
		serverPrivEd25519,
		serverPubEd25519,
	)
	if err != nil {
		t.Fatalf("Erreur lors de la configuration du serveur : %v", err)
	}

	clientSharedKey, clientErr := simulateClientSide(clientConn, serverPubEd25519)
	if clientErr != nil {
		t.Fatalf("Erreur côté client: %v", clientErr)
	}
	clientConn.Close()

	result := <-resultChan
	if result.Err != nil {
		t.Fatalf("Erreur côté serveur: %v", result.Err)
	}

	if !bytes.Equal(result.Key[:], clientSharedKey) {
		t.Fatalf("Les clés échangées ne correspondent pas.\nServeur : %x\nClient  : %x",
			result.Key[:], clientSharedKey)
	}
}

// simulateClientSide simule la logique du client :
// 1. Lit la clé publique Kyber + signature Ed25519 du serveur
// 2. Vérifie la signature
// 3. Reconstruit la clé publique Kyber
// 4. Encapsule un secret pour produire un ciphertext
// 5. Envoie ce ciphertext au serveur
// 6. Renvoie le secret local qui, si tout va bien, correspondra à celui du serveur
func simulateClientSide(conn net.Conn, serverPubEd25519 ed25519.PublicKey) ([]byte, error) {
	// 1) Lire la clé publique Kyber (pkBytes)
	pkBytes, err := readBytesWithLength(conn)
	if err != nil {
		return nil, fmt.Errorf("erreur lecture pkKyber : %v", err)
	}

	// 2) Lire la signature Ed25519
	signature, err := readBytesWithLength(conn)
	if err != nil {
		return nil, fmt.Errorf("erreur lecture signature : %v", err)
	}

	// 3) Vérifier la signature Ed25519 pour s'assurer que pkBytes n'a pas été modifié
	if !ed25519.Verify(serverPubEd25519, pkBytes, signature) {
		return nil, fmt.Errorf("signature Ed25519 invalide sur la clé publique Kyber")
	}

	// 4) Reconstruire la clé publique Kyber, en utilisant Unpack au lieu de UnmarshalBinary
	var pkServer kyber768.PublicKey
	// pkServer.Unpack panique si la taille est incorrecte, sinon ne retourne pas d'erreur
	pkServer.Unpack(pkBytes)

	// 5) Encapsuler => ciphertext (ct) et sharedKey (32 octets)
	ct := make([]byte, kyber768.CiphertextSize)
	sharedKey := make([]byte, kyber768.SharedKeySize)
	pkServer.EncapsulateTo(ct, sharedKey, nil)

	// 6) Envoyer le ciphertext au serveur
	if err := writeBytesWithLength(conn, ct); err != nil {
		return nil, fmt.Errorf("erreur d'envoi du ciphertext Kyber : %v", err)
	}

	// 7) Retourner la clé partagée du côté client
	return sharedKey, nil
}

// readBytesWithLength lit un uint32 (Big-Endian) puis lit ce nombre d'octets.
func readBytesWithLength(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}
	length := (uint32(lenBuf[0]) << 24) |
		(uint32(lenBuf[1]) << 16) |
		(uint32(lenBuf[2]) << 8) |
		uint32(lenBuf[3])

	data := make([]byte, length)
	if _, err := conn.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeBytesWithLength(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	lenBuf := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}

// ErrSignatureInvalid est retournée si la signature Ed25519 du serveur est invalide.
var ErrSignatureInvalid = &SignatureInvalidError{}

type SignatureInvalidError struct{}

func (e *SignatureInvalidError) Error() string {
	return "signature Ed25519 invalide"
}
