package tests

import (
	"testing"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// TestGenerateRandomKeySimple teste la génération de clés simples
func TestGenerateRandomKeySimple(t *testing.T) {
	key, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Vérifier que la clé n'est pas nulle
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Generated key is all zeros")
	}
}

// TestEstimateMessageOverheadSimple teste l'estimation d'overhead
func TestEstimateMessageOverheadSimple(t *testing.T) {
	overhead := communication.EstimateMessageOverhead(100)
	if overhead <= 0 {
		t.Errorf("Expected positive overhead, got %d", overhead)
	}
}

// TestValidateMessageIntegritySimple teste la validation d'intégrité
func TestValidateMessageIntegritySimple(t *testing.T) {
	// Test avec données invalides
	err := communication.ValidateMessageIntegrity("")
	if err == nil {
		t.Error("Expected error for empty data")
	}

	err = communication.ValidateMessageIntegrity("invalid")
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

// TestCompareConstantTimeSimple teste la comparaison en temps constant
func TestCompareConstantTimeSimple(t *testing.T) {
	data1 := []byte("test")
	data2 := []byte("test")
	data3 := []byte("different")

	if !communication.CompareConstantTime(data1, data2) {
		t.Error("Identical data should compare as equal")
	}

	if communication.CompareConstantTime(data1, data3) {
		t.Error("Different data should not compare as equal")
	}
}

// TestFileEncryptorCreationSimple teste la création d'un encrypteur de fichiers
func TestFileEncryptorCreationSimple(t *testing.T) {
	key, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := communication.NewFileEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	if encryptor == nil {
		t.Error("Encryptor should not be nil")
	}
}

// TestGetFileEncryptionOverheadSimple teste le calcul d'overhead de fichier
func TestGetFileEncryptionOverheadSimple(t *testing.T) {
	overhead := communication.GetFileEncryptionOverhead(1024)
	if overhead < 0 {
		t.Errorf("Overhead should be positive, got %d", overhead)
	}
}

// TestBasicEncryptionFunctionality teste les fonctions de base de chiffrement
func TestBasicEncryptionFunctionality(t *testing.T) {
	key, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("test message")

	// Test de chiffrement basique
	ciphertext, err := communication.EncryptNaClBox(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if ciphertext == "" {
		t.Error("Ciphertext should not be empty")
	}

	// Test de déchiffrement
	decrypted, err := communication.DecryptNaClBox(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
}

// TestMessageHistoryStats teste les statistiques d'historique
func TestMessageHistoryStats(t *testing.T) {
	communication.ResetMessageHistory()

	stats := communication.GetMessageHistoryStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}

	if totalSessions, ok := stats["total_sessions"].(int); ok && totalSessions != 0 {
		t.Errorf("Expected 0 sessions after reset, got %d", totalSessions)
	}
}

// TestKeyGenerationUniqueness teste l'unicité des clés générées
func TestKeyGenerationUniqueness(t *testing.T) {
	keys := make(map[string]bool)

	for i := 0; i < 10; i++ {
		key, err := communication.GenerateRandomKey(32)
		if err != nil {
			t.Fatalf("Failed to generate key %d: %v", i, err)
		}

		keyStr := string(key)
		if keys[keyStr] {
			t.Errorf("Duplicate key generated at iteration %d", i)
		}
		keys[keyStr] = true
	}
}

// TestEncryptionWithDifferentKeys teste le chiffrement avec différentes clés
func TestEncryptionWithDifferentKeys(t *testing.T) {
	key1, _ := communication.GenerateRandomKey(32)
	key2, _ := communication.GenerateRandomKey(32)

	plaintext := []byte("test data")

	// Chiffrer avec key1
	ciphertext1, err := communication.EncryptNaClBox(plaintext, key1)
	if err != nil {
		t.Fatalf("Failed to encrypt with key1: %v", err)
	}

	// Chiffrer avec key2
	ciphertext2, err := communication.EncryptNaClBox(plaintext, key2)
	if err != nil {
		t.Fatalf("Failed to encrypt with key2: %v", err)
	}

	// Les textes chiffrés devraient être différents
	if ciphertext1 == ciphertext2 {
		t.Error("Different keys should produce different ciphertexts")
	}

	// Essayer de déchiffrer avec la mauvaise clé
	_, err = communication.DecryptNaClBox(ciphertext1, key2)
	if err == nil {
		t.Error("Decryption with wrong key should fail")
	}
}

// TestValidateEncryptedDataSimple teste la validation de données chiffrées
func TestValidateEncryptedDataSimple(t *testing.T) {
	key, _ := communication.GenerateRandomKey(32)
	plaintext := []byte("test message")

	// Créer des données chiffrées valides
	ciphertext, err := communication.EncryptNaClBox(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Valider
	err = communication.ValidateEncryptedData(ciphertext)
	if err != nil {
		t.Errorf("Valid encrypted data failed validation: %v", err)
	}
}

// TestEncryptionEdgeCases teste les cas limites du chiffrement
func TestEncryptionEdgeCases(t *testing.T) {
	key, _ := communication.GenerateRandomKey(32)

	// Test avec données vides
	_, err := communication.EncryptNaClBox([]byte{}, key)
	if err == nil {
		t.Error("Empty data encryption should fail")
	}

	// Test avec clé vide
	_, err = communication.EncryptNaClBox([]byte("test"), []byte{})
	if err == nil {
		t.Error("Empty key encryption should fail")
	}
}

// TestSessionKeyDerivation teste la dérivation de clés de session
func TestSessionKeyDerivation(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)

	// Remplir avec des données différentes
	for i := range secret1 {
		secret1[i] = byte(i)
		secret2[i] = byte(255 - i)
	}

	key1 := communication.DeriveSessionKey(secret1)
	key2 := communication.DeriveSessionKey(secret2)

	// Les clés devraient être différentes
	if string(key1[:]) == string(key2[:]) {
		t.Error("Different secrets should produce different keys")
	}

	// La même clé devrait produire le même résultat
	key1Again := communication.DeriveSessionKey(secret1)
	if string(key1[:]) != string(key1Again[:]) {
		t.Error("Same secret should produce same key")
	}
}
