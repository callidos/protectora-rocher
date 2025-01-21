package tests

import (
	"encoding/base64"
	"testing"

	"protectora-rocher/pkg/communication" // Importation du bon package
)

var (
	testMasterKey = []byte("thisisaverysecuremasterkey!")
	testMessage   = "Message de test pour chiffrement"
)

// Test de dérivation des clés
func TestDeriveKeys(t *testing.T) {
	encryptionKey, hmacKey := communication.DeriveKeys(testMasterKey)
	if len(encryptionKey) != 16 || len(hmacKey) != 16 {
		t.Errorf("Les clés dérivées n'ont pas les bonnes longueurs")
	}
}

// Test du chiffrement et du déchiffrement avec des données valides
func TestEncryptionDecryption(t *testing.T) {
	ciphertext, err := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	if err != nil {
		t.Fatalf("Erreur de chiffrement : %v", err)
	}

	plaintext, err := communication.DecryptAESGCM(ciphertext, testMasterKey)
	if err != nil {
		t.Fatalf("Erreur de déchiffrement : %v", err)
	}

	if string(plaintext) != testMessage {
		t.Errorf("Le message déchiffré ne correspond pas au message original")
	}
}

// Test du déchiffrement de données corrompues
func TestDecryptCorruptedData(t *testing.T) {
	invalidCiphertext := base64.StdEncoding.EncodeToString([]byte("données corrompues"))

	_, err := communication.DecryptAESGCM(invalidCiphertext, testMasterKey)
	if err == nil {
		t.Errorf("Le déchiffrement de données corrompues devrait échouer")
	}
}

// Test de la génération HMAC
func TestGenerateHMAC(t *testing.T) {
	hmac1 := communication.GenerateHMAC(testMessage, testMasterKey)
	hmac2 := communication.GenerateHMAC(testMessage, testMasterKey)

	if hmac1 != hmac2 {
		t.Errorf("Les HMAC générés pour le même message ne sont pas identiques")
	}

	hmacDifferent := communication.GenerateHMAC("autre message", testMasterKey)
	if hmac1 == hmacDifferent {
		t.Errorf("Les HMAC pour des messages différents ne devraient pas être identiques")
	}
}
