package tests

import (
	"testing"

	"protectora-rocher/pkg/communication" // Importation du bon package
)

var (
	testMasterKey = []byte("thisisaverysecuremasterkey!")
	testMessage   = "Message de test pour chiffrement"
)

// Test de dérivation des clés
func TestDeriveKeys(t *testing.T) {
	encryptionKey, hmacKey, err := communication.DeriveKeys(testMasterKey)
	if err != nil {
		t.Fatalf("Erreur lors de la dérivation des clés : %v", err)
	}
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
	masterKey := []byte("thisisaverysecuremasterkey!")
	message := "Message sécurisé"

	encrypted, err := communication.EncryptAESGCM([]byte(message), masterKey)
	if err != nil {
		t.Fatalf("Erreur de chiffrement : %v", err)
	}

	// Corruption du message chiffré (modification d'un octet)
	corruptedCiphertext := encrypted[:len(encrypted)-5] + "XYZ123"

	_, err = communication.DecryptAESGCM(corruptedCiphertext, masterKey)
	if err == nil {
		t.Errorf("Le déchiffrement de données corrompues devrait échouer")
	} else {
		t.Logf("Expected failure for corrupted input, received error: %v", err)
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

func TestEncryptDecryptEdgeCases(t *testing.T) {
	testCases := []struct {
		input      string
		masterKey  []byte
		shouldFail bool
	}{
		{"", []byte("testkey"), true}, // Message vide doit échouer
		{"Short", []byte("shortkey"), false},
		{"Message très long....", []byte("longsecurekey123"), false},
		{"Corrupted", []byte("longsecurekey123"), true}, // Doit échouer
	}

	for _, tc := range testCases {
		encrypted, err := communication.EncryptAESGCM([]byte(tc.input), tc.masterKey)

		if tc.input == "" {
			if err == nil {
				t.Errorf("Expected failure for empty input, but encryption succeeded")
			} else {
				t.Logf("Expected error for empty input, received: %v", err)
			}
			continue
		}

		if err != nil {
			t.Errorf("Erreur de chiffrement pour l'entrée : %s, erreur : %v", tc.input, err)
			continue
		}

		// Corruption intentionnelle du message chiffré pour vérifier l'échec attendu
		if tc.shouldFail && tc.input == "Corrupted" {
			encrypted = encrypted[:len(encrypted)-1] + "X" // Corruption volontaire
		}

		decrypted, err := communication.DecryptAESGCM(encrypted, tc.masterKey)
		if tc.shouldFail {
			if err == nil {
				t.Errorf("Expected failure but got success for input: %s", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("Decryption failed for input: %s, error: %v", tc.input, err)
			} else if string(decrypted) != tc.input {
				t.Errorf("Le message déchiffré ne correspond pas au message original pour l'entrée : %s", tc.input)
			}
		}
	}
}

func TestDecryptAESGCMErrorCases(t *testing.T) {
	masterKey := []byte("thisisaverysecuremasterkey!")

	// Test des données vides
	_, err := communication.DecryptAESGCM("", masterKey)
	if err == nil {
		t.Errorf("Expected error for empty input, but got nil")
	}

	// Test avec des données non encodées en base64
	_, err = communication.DecryptAESGCM("invalid_base64_data", masterKey)
	if err == nil {
		t.Errorf("Expected error for invalid base64 data, but got nil")
	}

	// Test avec un message tronqué
	encrypted, _ := communication.EncryptAESGCM([]byte("Test message"), masterKey)
	truncatedCiphertext := encrypted[:len(encrypted)-5]
	_, err = communication.DecryptAESGCM(truncatedCiphertext, masterKey)
	if err == nil {
		t.Errorf("Expected error for truncated input, but got nil")
	}
}
