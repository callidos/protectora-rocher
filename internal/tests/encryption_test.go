package tests

import (
	"bytes"
	"fmt"
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

// Test encryption and decryption
func TestEncryptionDecryption(t *testing.T) {
	ciphertext, err := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := communication.DecryptAESGCM(ciphertext, testMasterKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != testMessage {
		t.Errorf("Decrypted message does not match original")
	}
}

// Test decryption with corrupted data
func TestDecryptCorruptedData(t *testing.T) {
	ciphertext, _ := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)

	corruptedCiphertext := ciphertext[:len(ciphertext)-4] + "XXXX" // Corrupting the last few characters

	_, err := communication.DecryptAESGCM(corruptedCiphertext, testMasterKey)
	if err == nil {
		t.Error("Decryption should fail for corrupted data")
	}
}

// Test HMAC generation consistency
func TestGenerateHMAC(t *testing.T) {
	key := []byte("secretkey")
	message := "test-message"

	hmac1 := communication.GenerateHMAC(message, key)
	hmac2 := communication.GenerateHMAC(message, key)

	if hmac1 != hmac2 {
		t.Errorf("Generated HMAC values do not match. Expected %s, got %s", hmac1, hmac2)
	}
}

// Test edge cases for encryption/decryption
func TestEncryptDecryptEdgeCases(t *testing.T) {
	testCases := []struct {
		input      string
		masterKey  []byte
		shouldFail bool
	}{
		{"", testMasterKey, true},       // Empty input should fail
		{"Short", testMasterKey, false}, // Short input
		{"Long test message for security", testMasterKey, false},
		{"CorruptMe", testMasterKey, true}, // Will corrupt later
	}

	for _, tc := range testCases {
		ciphertext, err := communication.EncryptAESGCM([]byte(tc.input), tc.masterKey)

		// Correction : gestion correcte des entrées vides
		if err != nil {
			if tc.shouldFail && tc.input == "" {
				t.Logf("Expected failure for empty input: %q", tc.input)
				continue
			}
			t.Errorf("Unexpected encryption failure for input: %q, error: %v", tc.input, err)
			continue
		}

		if tc.shouldFail && tc.input == "CorruptMe" {
			ciphertext = ciphertext[:len(ciphertext)-1] + "X" // Corrupt the last character
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

// Test error cases for decryption
func TestDecryptAESGCMErrorCases(t *testing.T) {
	_, err := communication.DecryptAESGCM("", testMasterKey)
	if err == nil {
		t.Error("Expected error for empty input")
	}

	_, err = communication.DecryptAESGCM("invalid_base64", testMasterKey)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	ciphertext, _ := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)
	truncatedCiphertext := ciphertext[:len(ciphertext)-5]
	_, err = communication.DecryptAESGCM(truncatedCiphertext, testMasterKey)
	if err == nil {
		t.Error("Expected error for truncated ciphertext")
	}
}

// Test encryption and decryption with large data
func TestEncryptionDecryptionPerformance(t *testing.T) {
	largeData := make([]byte, 1<<20) // 1 MB of data

	ciphertext, err := communication.EncryptAESGCM(largeData, testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed for large data: %v", err)
	}

	decrypted, err := communication.DecryptAESGCM(ciphertext, testMasterKey)
	if err != nil {
		t.Fatalf("Decryption failed for large data: %v", err)
	}

	if len(decrypted) != len(largeData) {
		t.Errorf("Expected decrypted size %d, got %d", len(largeData), len(decrypted))
	}
}

// Test decryption with wrong key
func TestDecryptWithWrongKey(t *testing.T) {
	wrongKey := []byte("wrongkeyfortesting")
	ciphertext, _ := communication.EncryptAESGCM([]byte(testMessage), testMasterKey)

	_, err := communication.DecryptAESGCM(ciphertext, wrongKey)
	if err == nil {
		t.Errorf("Decryption should fail with wrong key")
	}
}

func TestEncryptDecryptBinaryData(t *testing.T) {
	binaryData := []byte{0x00, 0xFF, 0xA5, 0x4B, 0x7E}
	ciphertext, err := communication.EncryptAESGCM(binaryData, testMasterKey)
	if err != nil {
		t.Fatalf("Encryption failed for binary data: %v", err)
	}

	decrypted, err := communication.DecryptAESGCM(ciphertext, testMasterKey)
	if err != nil || !bytes.Equal(decrypted, binaryData) {
		t.Errorf("Decrypted binary data does not match original")
	}
}

func TestCiphertextLength(t *testing.T) {
	plaintext := []byte("plaintext")
	ciphertext, _ := communication.EncryptAESGCM(plaintext, testMasterKey)

	if len(ciphertext) <= len(plaintext) {
		t.Errorf("Ciphertext should be longer than plaintext")
	}
}

func TestEncryptionRandomness(t *testing.T) {
	message := []byte("unique message")
	cipher1, _ := communication.EncryptAESGCM(message, testMasterKey)
	cipher2, _ := communication.EncryptAESGCM(message, testMasterKey)

	if cipher1 == cipher2 {
		t.Errorf("Encryption should produce different outputs for the same plaintext")
	}
}

func TestConcurrentEncryptionDecryption(t *testing.T) {
	message := []byte("concurrent test")
	const numGoroutines = 10
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			cipher, err := communication.EncryptAESGCM(message, testMasterKey)
			if err != nil {
				errors <- fmt.Errorf("encryption failed: %v", err)
				return
			}

			decrypted, err := communication.DecryptAESGCM(cipher, testMasterKey)
			if err != nil || string(decrypted) != string(message) {
				errors <- fmt.Errorf("decryption failed")
			}
			errors <- nil
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errors; err != nil {
			t.Error(err)
		}
	}
}
