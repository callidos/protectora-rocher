package tests

import (
	"crypto/hmac"
	"encoding/base64"
	"protectora-rocher/pkg/communication"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandleConnection(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\nFIN_SESSION\n")

	doneChan := make(chan bool)
	go func() {
		communication.HandleConnection(mockConn, mockConn, sharedKey)
		doneChan <- true
	}()

	select {
	case <-doneChan:
		validateWelcomeMessage(t, mockConn.Buffer.String(), sharedKey, "testuser")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout exceeded")
	}
}

func TestRejectCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\nmessage-corrompu|mauvaisHMAC\nFIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)
	time.Sleep(1 * time.Second)

	if strings.Contains(mockConn.Buffer.String(), "Message reçu avec succès.") {
		t.Errorf("Corrupted message should have been rejected")
	}
}

func TestHandleConnectionWithError(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Test with empty username
	mockConn.Buffer.WriteString("\n")

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		communication.HandleConnection(mockConn, mockConn, sharedKey)
	}()

	wg.Wait()

	output := mockConn.Buffer.String()
	expectedErrorMessage := "Erreur: Impossible de lire le nom d'utilisateur ou nom d'utilisateur vide"
	if !strings.Contains(output, expectedErrorMessage) {
		t.Errorf("Expected error message: %s, but got: %s", expectedErrorMessage, output)
	}
}

func TestHandleConnectionSessionDuration(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\nFIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)
	time.Sleep(3 * time.Second)

	if mockConn.Buffer.Len() == 0 {
		t.Errorf("No messages exchanged during session")
	}
}

func TestHandleMultipleMessages(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	messages := []string{"Message 1", "Message 2", "Message 3"}

	for _, msg := range messages {
		encrypted, _ := communication.EncryptAESGCM([]byte(msg), sharedKey)
		hmacValue := communication.GenerateHMAC(encrypted, sharedKey)
		mockConn.Buffer.WriteString(encrypted + "|" + hmacValue + "\n")
	}
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)
	time.Sleep(2 * time.Second)

	if !containsDecryptedAck(mockConn.Buffer.String(), "Message reçu avec succès.", sharedKey) {
		t.Errorf("Acknowledgment was not received")
	}
}

func TestInvalidUsernameHandling(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Simuler un nom d'utilisateur vide en envoyant une ligne vide
	mockConn.Buffer.WriteString("\nFIN_SESSION\n")

	// Créer un canal pour vérifier si la connexion a été fermée
	doneChan := make(chan bool)

	// Lancer HandleConnection dans une goroutine
	go func() {
		communication.HandleConnection(mockConn, mockConn, sharedKey)
		doneChan <- true
	}()

	// Attendre un délai et vérifier si la connexion a été fermée
	select {
	case <-doneChan:
		output := mockConn.Buffer.String()
		if !strings.Contains(output, "Erreur: Impossible de lire le nom d'utilisateur ou nom d'utilisateur vide") {
			t.Errorf("Session should not start with empty username, but it did: %s", output)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout exceeded, connection should have been closed")
	}
}

func TestEmptyMessageHandling(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n|\nFIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)
	time.Sleep(1 * time.Second)

	if strings.Contains(mockConn.Buffer.String(), "Message reçu avec succès.") {
		t.Errorf("Empty message should not be acknowledged")
	}
}

// containsDecryptedAck vérifie si un accusé de réception déchiffré est trouvé.
func containsDecryptedAck(fullOutput, expectedAck string, sharedKey []byte) bool {
	for _, line := range strings.Split(strings.TrimSpace(fullOutput), "\n") {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		encrypted, receivedHMAC := parts[0], parts[1]

		expectedHMAC := communication.GenerateHMAC(encrypted, sharedKey)
		if expectedHMAC != strings.TrimSpace(receivedHMAC) {
			continue
		}

		decrypted, err := communication.DecryptAESGCM(encrypted, sharedKey)
		if err == nil && string(decrypted) == expectedAck {
			return true
		}
	}
	return false
}

// validateWelcomeMessage valide le message de bienvenue reçu.
func validateWelcomeMessage(t *testing.T, output string, sharedKey []byte, username string) {
	parts := strings.SplitN(strings.TrimSpace(output), "|", 2)
	if len(parts) < 2 {
		t.Fatalf("Malformed received message: %s", output)
	}

	encryptedMessage, receivedHMAC := parts[0], strings.TrimSpace(parts[1])
	expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)

	expectedHMACBytes, _ := base64.StdEncoding.DecodeString(expectedHMAC)
	receivedHMACBytes, _ := base64.StdEncoding.DecodeString(receivedHMAC)

	if !hmac.Equal(expectedHMACBytes, receivedHMACBytes) {
		t.Fatalf("HMAC mismatch. Expected: %s, Got: %s", expectedHMAC, receivedHMAC)
	}

	decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	expectedWelcomeMessage := "Bienvenue " + username + " sur le serveur sécurisé."
	if string(decryptedMessage) != expectedWelcomeMessage {
		t.Errorf("Unexpected welcome message. Got: %s", decryptedMessage)
	}
}
