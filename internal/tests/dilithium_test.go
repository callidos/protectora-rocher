package tests

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"os"
	"testing"

	// Import du package communication depuis "protectora-rocher/pkg/communication"
	"protectora-rocher/pkg/communication"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

// TestHexBytes vérifie l'encodage et le décodage hex via le type HexBytes du package communication
func TestHexBytes(t *testing.T) {
	// On utilise la structure HexBytes exportée du package communication
	original := communication.HexBytes("message_test")

	// Test MarshalJSON
	jsonData, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("Erreur lors de l'encodage JSON: %v", err)
	}
	expectedHex := `"6d6573736167655f74657374"`
	if string(jsonData) != expectedHex {
		t.Fatalf("Encodage JSON incorrect, attendu %s, obtenu %s", expectedHex, string(jsonData))
	}

	// Test UnmarshalJSON
	var decoded communication.HexBytes
	err = decoded.UnmarshalJSON(jsonData)
	if err != nil {
		t.Fatalf("Erreur lors du décodage JSON: %v", err)
	}

	if !bytes.Equal(original, decoded) {
		t.Fatalf("Décodage incorrect, attendu %s, obtenu %s", original, decoded)
	}
}

// TestGunzip vérifie la décompression via la fonction Gunzip exportée
func TestGunzip(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte("test data"))
	if err != nil {
		t.Fatalf("Erreur de compression: %v", err)
	}
	writer.Close()

	// On appelle la fonction Gunzip depuis communication
	decompressed, err := communication.Gunzip(buf.Bytes())
	if err != nil {
		t.Fatalf("Erreur lors de la décompression: %v", err)
	}
	expected := "test data"
	if string(decompressed) != expected {
		t.Fatalf("Données décompressées incorrectes, attendu %s, obtenu %s", expected, string(decompressed))
	}
}

// TestReadGzip vérifie la lecture et la décompression d'un fichier gzip via la fonction ReadGzip
func TestReadGzip(t *testing.T) {
	testData := []byte("test gzip content")
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(testData)
	if err != nil {
		t.Fatalf("Erreur de compression: %v", err)
	}
	writer.Close()

	// Écriture des données compressées dans un fichier temporaire
	tmpFile, err := os.CreateTemp("", "testgzip")
	if err != nil {
		t.Fatalf("Erreur lors de la création du fichier temporaire: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(buf.Bytes())
	if err != nil {
		t.Fatalf("Erreur lors de l'écriture dans le fichier temporaire: %v", err)
	}
	tmpFile.Close()

	// Lecture et décompression via la fonction ReadGzip du package communication
	readData, err := communication.ReadGzip(tmpFile.Name())
	if err != nil {
		t.Fatalf("Erreur lors de la lecture du fichier gzip: %v", err)
	}
	if !bytes.Equal(readData, testData) {
		t.Fatalf("Données incorrectes lues depuis le fichier gzip")
	}
}

// TestDilithium lance un ensemble de sous-tests pour la génération et la vérification de clés
func TestDilithium(t *testing.T) {
	t.Run("KeyGen", func(t *testing.T) {
		testKeyGeneration(t)
	})
	t.Run("SigGen", func(t *testing.T) {
		testSignatureGeneration(t)
	})
	t.Run("SigVer", func(t *testing.T) {
		testSignatureVerification(t)
	})
}

// testKeyGeneration vérifie la génération de clés Dilithium
func testKeyGeneration(t *testing.T) {
	pk, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clés: %v", err)
	}
	if pk == nil || sk == nil {
		t.Fatal("Les clés générées sont nulles")
	}
	t.Logf("Clé publique: %x", pk.Bytes())
	t.Logf("Clé privée: %x", sk.Bytes())
}

// testSignatureGeneration vérifie la génération de signature
func testSignatureGeneration(t *testing.T) {
	_, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clés: %v", err)
	}

	message := []byte("Message à signer")
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(sk, message, signature)

	if len(signature) != mode2.SignatureSize {
		t.Fatalf("Taille de signature incorrecte : attendue %d, obtenue %d",
			mode2.SignatureSize, len(signature))
	}

	t.Logf("Signature: %x", signature)
}

// testSignatureVerification vérifie la validité d'une signature
func testSignatureVerification(t *testing.T) {
	pk, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clés: %v", err)
	}

	message := []byte("Message à signer")
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(sk, message, signature)

	// Vérification valide
	if !mode2.Verify(pk, message, signature) {
		t.Fatal("La signature est invalide alors qu'elle devrait être valide")
	}

	// Vérification invalide
	invalidMessage := []byte("Message falsifié")
	if mode2.Verify(pk, invalidMessage, signature) {
		t.Fatal("La signature a été validée alors qu'elle est invalide")
	}

	t.Log("Vérification de signature réussie")
}
