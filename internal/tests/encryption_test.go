package tests

import (
	"testing"

	"protectora-rocher/pkg/communication"
)

var (
	testMasterKey = []byte("thisisaverysecuremasterkey!")
	testMessage   = "Test encryption message"
)

// Test key derivation
func TestDeriveKeys(t *testing.T) {
	encryptionKey, hmacKey, err := communication.DeriveKeys(testMasterKey)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}
	if len(encryptionKey) != 16 || len(hmacKey) != 16 {
		t.Errorf("Derived keys have incorrect lengths")
	}
}

// Test encryption and decryption with valid data
func TestEncryptionDecryption(t *testing.T) {
	ciphertext, err := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	plaintext, err := communication.DecryptAESGCM(ciphertext, testMasterKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(plaintext) != testMessage {
		t.Errorf("Decrypted message does not match original")
	}
}

// Test decryption with corrupted data
func TestDecryptCorruptedData(t *testing.T) {
	ciphertext, err := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupting ciphertext by modifying last character
	corruptedCiphertext := ciphertext[:len(ciphertext)-5] + "XYZ123"

	_, err = communication.DecryptAESGCM(corruptedCiphertext, testMasterKey)
	if err == nil {
		t.Errorf("Decryption should fail for corrupted data")
	}
}

// Test HMAC generation
func TestGenerateHMAC(t *testing.T) {
	key := []byte("secretkey")
	message := "test-message"

	hmac1 := communication.GenerateHMAC(message, key)
	hmac2 := communication.GenerateHMAC(message, key)

	if hmac1 != hmac2 {
		t.Errorf("HMAC mismatch. Expected %s, got %s", hmac1, hmac2)
	}
}

// Test encryption and decryption edge cases
func TestEncryptDecryptEdgeCases(t *testing.T) {
	testCases := []struct {
		input      string
		masterKey  []byte
		shouldFail bool
	}{
		{"", []byte("testkey"), true}, // Empty message should fail
		{"Short", testMasterKey, false},
		{"Long test message for security", testMasterKey, false},
		{"Corrupted", testMasterKey, true}, // Expect failure after corruption
	}

	for _, tc := range testCases {
		ciphertext, err := communication.EncryptAESGCM([]byte(tc.input), tc.masterKey)

		if tc.shouldFail && tc.input == "" {
			if err == nil {
				t.Errorf("Expected encryption failure for empty input: %q", tc.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Encryption failed for input: %q, error: %v", tc.input, err)
			continue
		}

		// Corrupt ciphertext if needed
		if tc.shouldFail && tc.input == "Corrupted" {
			ciphertext = ciphertext[:len(ciphertext)-1] + "X"
		}

		decrypted, err := communication.DecryptAESGCM(ciphertext, tc.masterKey)
		if tc.shouldFail {
			if err == nil {
				t.Errorf("Expected failure but succeeded for input: %q", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("Decryption failed for input: %q, error: %v", tc.input, err)
			} else if string(decrypted) != tc.input {
				t.Errorf("Decrypted message does not match original for input: %q", tc.input)
			}
		}
	}
}

// Test decryption error cases
func TestDecryptAESGCMErrorCases(t *testing.T) {
	_, err := communication.DecryptAESGCM("", testMasterKey)
	if err == nil {
		t.Error("Expected error for empty input")
	}

	_, err = communication.DecryptAESGCM("invalid_base64", testMasterKey)
	if err == nil {
		t.Error("Expected error for invalid base64 data")
	}

	encrypted, _ := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	truncatedCiphertext := encrypted[:len(encrypted)-5]
	_, err = communication.DecryptAESGCM(truncatedCiphertext, testMasterKey)
	if err == nil {
		t.Error("Expected error for truncated input")
	}
}

// Test encryption/decryption performance
func TestEncryptionDecryptionPerformance(t *testing.T) {
	largeMessage := make([]byte, 1<<20) // 1 MB data

	encrypted, err := communication.EncryptAESGCM(largeMessage, testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed for large data: %v", err)
	}

	_, err = communication.DecryptAESGCM(encrypted, testMasterKey)
	if err != nil {
		t.Fatalf("Decryption failed for large data: %v", err)
	}
}

// Test decryption with incorrect key
func TestDecryptWithWrongKey(t *testing.T) {
	wrongKey := []byte("wrongkeyfortesting")
	ciphertext, err := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = communication.DecryptAESGCM(ciphertext, wrongKey)
	if err == nil {
		t.Errorf("Decryption should fail with wrong key")
	}
}
