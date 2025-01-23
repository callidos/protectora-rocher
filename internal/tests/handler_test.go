package tests

import (
	"crypto/hmac"
	"encoding/base64"
	"protectora-rocher/pkg/communication"
	"strings"
	"testing"
	"time"
)

// Test de la gestion de la connexion avec un utilisateur valide
func TestHandleConnection(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	// Démarrer la gestion de connexion dans une goroutine
	doneChan := make(chan bool)
	go func() {
		communication.HandleConnection(mockConn, mockConn, sharedKey)
		doneChan <- true
	}()

	select {
	case <-doneChan:
		output := strings.TrimSpace(mockConn.Buffer.String())
		t.Logf("Output buffer: %s", output)

		parts := strings.SplitN(output, "|", 2)
		if len(parts) < 2 {
			t.Fatalf("Le message reçu est mal formé : %s", output)
		}

		encryptedMessage := parts[0]
		receivedHMAC := strings.TrimSpace(parts[1])

		expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)

		expectedHMACBytes, _ := base64.StdEncoding.DecodeString(expectedHMAC)
		receivedHMACBytes, _ := base64.StdEncoding.DecodeString(receivedHMAC)

		if !hmac.Equal(expectedHMACBytes, receivedHMACBytes) {
			t.Fatalf("HMAC invalide, message corrompu. Attendu: %s, Reçu: %s", expectedHMAC, receivedHMAC)
		}

		decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			t.Fatalf("Erreur lors du déchiffrement du message de bienvenue : %v", err)
		}

		expectedWelcomeMessage := "Bienvenue testuser sur le serveur sécurisé."
		if string(decryptedMessage) != expectedWelcomeMessage {
			t.Errorf("Le message de bienvenue attendu n'a pas été reçu. Reçu : %s", decryptedMessage)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Le test a dépassé le délai d'attente.")
	}
}

// Test du rejet de messages corrompus
func TestRejectCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("message-corrompu|mauvaisHMAC\n")
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)

	time.Sleep(1 * time.Second)

	output := mockConn.Buffer.String()
	t.Logf("Output buffer for corrupted message: %s", output)

	if strings.Contains(output, "Message reçu avec succès.") {
		t.Errorf("Le message corrompu aurait dû être rejeté")
	}
}

// Test de gestion d'une connexion interrompue
func TestHandleConnectionWithError(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)

	time.Sleep(1 * time.Second)

	t.Log("Test de gestion des connexions avec interruption")
}

// Test de la durée de session
func TestHandleConnectionSessionDuration(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)

	time.Sleep(3 * time.Second)

	if mockConn.Buffer.Len() == 0 {
		t.Errorf("Aucun message échangé pendant la session")
	}
}

// Test de réception de plusieurs messages en séquence
func TestHandleMultipleMessages(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")

	messages := []string{"Message 1", "Message 2", "Message 3"}
	for _, msg := range messages {
		encryptedMessage, _ := communication.EncryptAESGCM([]byte(msg), sharedKey)
		hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
		mockConn.Buffer.WriteString(encryptedMessage + "|" + hmac + "\n")
	}

	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, mockConn, sharedKey)

	time.Sleep(2 * time.Second)

	output := mockConn.Buffer.String()
	t.Logf("Output buffer after processing: %s", output)

	if !containsDecryptedAck(output, "Message reçu avec succès.", sharedKey) {
		t.Errorf("L'accusé de réception du message n'a pas été reçu")
	}
}

// containsDecryptedAck vérifie si un accusé de réception est présent après déchiffrement.
func containsDecryptedAck(fullOutput string, expectedAck string, sharedKey []byte) bool {
	lines := strings.Split(strings.TrimSpace(fullOutput), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		encrypted := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := communication.GenerateHMAC(encrypted, sharedKey)
		if expectedHMAC != strings.TrimSpace(receivedHMAC) {
			continue
		}

		decrypted, err := communication.DecryptAESGCM(encrypted, sharedKey)
		if err != nil {
			continue
		}

		if string(decrypted) == expectedAck {
			return true
		}
	}
	return false
}
