package tests

import (
	"bytes"
	"testing"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// TestEncryptDecryptBasic teste le chiffrement/déchiffrement de base
func TestEncryptDecryptBasic(t *testing.T) {
	// Générer une clé maître
	masterKey, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Données de test
	plaintext := []byte("This is a test message for encryption")

	// Chiffrer
	ciphertext, err := communication.EncryptNaClBox(plaintext, masterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Vérifier que le texte chiffré n'est pas vide
	if ciphertext == "" {
		t.Fatal("Ciphertext is empty")
	}

	// Déchiffrer
	decrypted, err := communication.DecryptNaClBox(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Vérifier que les données décryptées correspondent aux originales
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestEncryptDecryptWithAdditionalData teste le chiffrement avec données additionnelles
func TestEncryptDecryptWithAdditionalData(t *testing.T) {
	masterKey, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	plaintext := []byte("Secret message")
	additionalData := []byte("context-info")

	// Chiffrer avec données additionnelles
	ciphertext, err := communication.EncryptWithAdditionalData(plaintext, masterKey, additionalData)
	if err != nil {
		t.Fatalf("Encryption with additional data failed: %v", err)
	}

	// Déchiffrer avec les bonnes données additionnelles
	decrypted, err := communication.DecryptWithAdditionalData(ciphertext, masterKey, additionalData)
	if err != nil {
		t.Fatalf("Decryption with additional data failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match original")
	}
}

// TestDecryptWithWrongAdditionalData teste le déchiffrement avec de mauvaises données additionnelles
func TestDecryptWithWrongAdditionalData(t *testing.T) {
	masterKey, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	plaintext := []byte("Secret message")
	correctAD := []byte("correct-context")
	wrongAD := []byte("wrong-context")

	// Chiffrer avec les bonnes données additionnelles
	ciphertext, err := communication.EncryptWithAdditionalData(plaintext, masterKey, correctAD)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Essayer de déchiffrer avec de mauvaises données additionnelles
	_, err = communication.DecryptWithAdditionalData(ciphertext, masterKey, wrongAD)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong additional data, but it succeeded")
	}
}

// TestEncryptDecryptWithWrongKey teste le déchiffrement avec une mauvaise clé
func TestEncryptDecryptWithWrongKey(t *testing.T) {
	key1, _ := communication.GenerateRandomKey(32)
	key2, _ := communication.GenerateRandomKey(32)

	plaintext := []byte("Test message")

	// Chiffrer avec key1
	ciphertext, err := communication.EncryptNaClBox(plaintext, key1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Essayer de déchiffrer avec key2
	_, err = communication.DecryptNaClBox(ciphertext, key2)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong key, but it succeeded")
	}
}

// TestEncryptEmptyData teste le chiffrement de données vides
func TestEncryptEmptyData(t *testing.T) {
	masterKey, _ := communication.GenerateRandomKey(32)

	// Essayer de chiffrer des données vides
	_, err := communication.EncryptNaClBox([]byte{}, masterKey)
	if err == nil {
		t.Fatal("Expected encryption of empty data to fail")
	}

	_, err = communication.EncryptNaClBox(nil, masterKey)
	if err == nil {
		t.Fatal("Expected encryption of nil data to fail")
	}
}

// TestEncryptWithEmptyKey teste le chiffrement avec une clé vide
func TestEncryptWithEmptyKey(t *testing.T) {
	plaintext := []byte("Test message")

	// Essayer avec une clé vide
	_, err := communication.EncryptNaClBox(plaintext, []byte{})
	if err == nil {
		t.Fatal("Expected encryption with empty key to fail")
	}

	// Essayer avec une clé nil
	_, err = communication.EncryptNaClBox(plaintext, nil)
	if err == nil {
		t.Fatal("Expected encryption with nil key to fail")
	}
}

// TestEncryptLargeData teste le chiffrement de grandes quantités de données
func TestEncryptLargeData(t *testing.T) {
	masterKey, _ := communication.GenerateRandomKey(32)

	// Créer des données de ~5MB (en dessous de la limite de 10MB)
	largeData := make([]byte, 5*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Chiffrer
	ciphertext, err := communication.EncryptNaClBox(largeData, masterKey)
	if err != nil {
		t.Fatalf("Encryption of large data failed: %v", err)
	}

	// Déchiffrer
	decrypted, err := communication.DecryptNaClBox(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("Decryption of large data failed: %v", err)
	}

	// Vérifier l'intégrité
	if !bytes.Equal(decrypted, largeData) {
		t.Error("Large data decryption failed - data doesn't match")
	}
}

// TestEncryptTooLargeData teste le chiffrement de données trop volumineuses
func TestEncryptTooLargeData(t *testing.T) {
	masterKey, _ := communication.GenerateRandomKey(32)

	// Créer des données > 10MB (au-dessus de la limite)
	tooLargeData := make([]byte, 11*1024*1024)

	// Cela devrait échouer
	_, err := communication.EncryptNaClBox(tooLargeData, masterKey)
	if err == nil {
		t.Fatal("Expected encryption of too large data to fail")
	}
}

// TestValidateEncryptedData teste la validation des données chiffrées
func TestValidateEncryptedData(t *testing.T) {
	masterKey, _ := communication.GenerateRandomKey(32)
	plaintext := []byte("Test message")

	// Chiffrer des données valides
	ciphertext, err := communication.EncryptNaClBox(plaintext, masterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Valider les données chiffrées
	err = communication.ValidateEncryptedData(ciphertext)
	if err != nil {
		t.Errorf("Validation of valid encrypted data failed: %v", err)
	}

	// Tester avec des données invalides
	invalidCases := []string{
		"",                   // vide
		"invalid",            // trop court
		"not-base64-at-all!", // base64 invalide
	}

	for _, invalid := range invalidCases {
		err = communication.ValidateEncryptedData(invalid)
		if err == nil {
			t.Errorf("Expected validation to fail for: %q", invalid)
		}
	}
}

// TestCompareConstantTime teste la comparaison en temps constant
func TestCompareConstantTime(t *testing.T) {
	// Données identiques
	data1 := []byte("test data")
	data2 := []byte("test data")

	if !communication.CompareConstantTime(data1, data2) {
		t.Error("Identical data should compare as equal")
	}

	// Données différentes
	data3 := []byte("different data")
	if communication.CompareConstantTime(data1, data3) {
		t.Error("Different data should not compare as equal")
	}

	// Longueurs différentes
	data4 := []byte("test")
	if communication.CompareConstantTime(data1, data4) {
		t.Error("Data with different lengths should not compare as equal")
	}

	// Cas spéciaux
	empty1 := []byte{}
	empty2 := []byte{}
	if !communication.CompareConstantTime(empty1, empty2) {
		t.Error("Empty slices should compare as equal")
	}

	if communication.CompareConstantTime(empty1, data1) {
		t.Error("Empty and non-empty should not compare as equal")
	}
}

// TestGenerateRandomKey teste la génération de clés aléatoires
func TestGenerateRandomKey(t *testing.T) {
	// Tester différentes tailles
	sizes := []int{16, 32, 64}

	for _, size := range sizes {
		key, err := communication.GenerateRandomKey(size)
		if err != nil {
			t.Errorf("Failed to generate key of size %d: %v", size, err)
			continue
		}

		if len(key) != size {
			t.Errorf("Expected key size %d, got %d", size, len(key))
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
			t.Errorf("Generated key is all zeros for size %d", size)
		}
	}

	// Tester les tailles invalides
	invalidSizes := []int{-1, 0, 65}
	for _, size := range invalidSizes {
		_, err := communication.GenerateRandomKey(size)
		if err == nil {
			t.Errorf("Expected error for invalid key size %d", size)
		}
	}
}

// TestKeyUniqueness teste que les clés générées sont uniques
func TestKeyUniqueness(t *testing.T) {
	keys := make(map[string]bool)
	keyCount := 100

	for i := 0; i < keyCount; i++ {
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

	if len(keys) != keyCount {
		t.Errorf("Expected %d unique keys, got %d", keyCount, len(keys))
	}
}

// BenchmarkEncryption benchmark pour le chiffrement
func BenchmarkEncryption(b *testing.B) {
	masterKey, _ := communication.GenerateRandomKey(32)
	plaintext := []byte("This is a benchmark test message that is reasonably sized")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := communication.EncryptNaClBox(plaintext, masterKey)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkDecryption benchmark pour le déchiffrement
func BenchmarkDecryption(b *testing.B) {
	masterKey, _ := communication.GenerateRandomKey(32)
	plaintext := []byte("This is a benchmark test message that is reasonably sized")

	// Pré-chiffrer le message
	ciphertext, err := communication.EncryptNaClBox(plaintext, masterKey)
	if err != nil {
		b.Fatalf("Pre-encryption failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := communication.DecryptNaClBox(ciphertext, masterKey)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
