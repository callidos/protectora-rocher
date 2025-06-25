package tests

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// generateUniqueSessionID génère un ID de session unique
func generateUniqueSessionID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), time.Now().Unix())
}

// TestSendReceiveMessage teste l'envoi et la réception de messages de base
func TestSendReceiveMessage(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	// Générer une clé de test
	key, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Message de test
	testMessage := "Hello, secure world!"
	sessionID := generateUniqueSessionID("test-send-receive")

	// Buffer pour simuler la connexion
	var buffer bytes.Buffer

	// Envoyer le message avec session unique
	err = communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Vérifier que des données ont été écrites
	if buffer.Len() == 0 {
		t.Fatal("No data written to buffer")
	}

	// Recevoir le message avec la même session
	receivedMessage, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Vérifier que le message reçu correspond au message envoyé
	if receivedMessage != testMessage {
		t.Errorf("Expected message %q, got %q", testMessage, receivedMessage)
	}
}

// TestSendReceiveMessageWithSession teste l'envoi et la réception avec session
func TestSendReceiveMessageWithSession(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, err := communication.GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testMessage := "Session message test"
	sessionID := generateUniqueSessionID("test-session")

	var buffer bytes.Buffer

	// Envoyer avec session
	err = communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message with session: %v", err)
	}

	// Recevoir avec session
	receivedMessage, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message with session: %v", err)
	}

	if receivedMessage != testMessage {
		t.Errorf("Expected message %q, got %q", testMessage, receivedMessage)
	}
}

// TestInvalidKey teste le comportement avec une clé invalide
func TestInvalidKey(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key1, _ := communication.GenerateRandomKey(32)
	key2, _ := communication.GenerateRandomKey(32)

	testMessage := "Test message"
	sessionID := generateUniqueSessionID("test-invalid-key")
	var buffer bytes.Buffer

	// Envoyer avec key1
	err := communication.SendMessageWithSession(&buffer, testMessage, key1, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Essayer de recevoir avec key2 (différente)
	_, err = communication.ReceiveMessageWithSession(&buffer, key2, sessionID)
	if err == nil {
		t.Fatal("Expected error when using wrong key, but got none")
	}
}

// TestEmptyMessage teste l'envoi de messages vides
func TestEmptyMessage(t *testing.T) {
	key, _ := communication.GenerateRandomKey(32)
	var buffer bytes.Buffer

	// Essayer d'envoyer un message vide
	err := communication.SendMessage(&buffer, "", key, 1, 0)
	if err == nil {
		t.Fatal("Expected error for empty message, but got none")
	}
}

// TestLargeMessage teste l'envoi de messages volumineux
func TestLargeMessage(t *testing.T) {
	key, _ := communication.GenerateRandomKey(32)

	// Créer un message très large (> 10MB)
	largeMessage := strings.Repeat("A", 11*1024*1024) // 11MB
	var buffer bytes.Buffer

	// Cela devrait échouer car le message est trop grand
	err := communication.SendMessage(&buffer, largeMessage, key, 1, 0)
	if err == nil {
		t.Fatal("Expected error for large message, but got none")
	}
}

// TestMultipleMessages teste l'envoi de plusieurs messages en séquence avec sessions séparées
func TestMultipleMessages(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)

	messages := []string{
		"First message",
		"Second message",
		"Third message",
	}

	// Utiliser des sessions séparées pour chaque message
	for i, msg := range messages {
		var buffer bytes.Buffer
		sessionID := generateUniqueSessionID(fmt.Sprintf("test-multi-%d", i))

		err := communication.SendMessageWithSession(&buffer, msg, key, uint64(i+1), 0, sessionID)
		if err != nil {
			t.Fatalf("Failed to send message %d: %v", i+1, err)
		}

		receivedMsg, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i+1, err)
		}

		if receivedMsg != msg {
			t.Errorf("Message %d: expected %q, got %q", i+1, msg, receivedMsg)
		}
	}
}

// TestMessageWithTTL teste les messages avec TTL
func TestMessageWithTTL(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "TTL test message"
	sessionID := generateUniqueSessionID("test-ttl")
	var buffer bytes.Buffer

	// Envoyer avec TTL de 3600 secondes (1 heure - suffisant pour le test)
	err := communication.SendMessageWithSession(&buffer, testMessage, key, 1, 3600, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message with TTL: %v", err)
	}

	// Recevoir immédiatement (devrait marcher)
	receivedMessage, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	if receivedMessage != testMessage {
		t.Errorf("Expected message %q, got %q", testMessage, receivedMessage)
	}
}

// TestSessionIsolation teste l'isolation des sessions
func TestSessionIsolation(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Session isolation test"

	session1 := generateUniqueSessionID("session-1")
	session2 := generateUniqueSessionID("session-2")

	var buffer bytes.Buffer

	// Envoyer avec session1
	err := communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, session1)
	if err != nil {
		t.Fatalf("Failed to send message with session1: %v", err)
	}

	// Essayer de recevoir avec session2 (devrait échouer)
	_, err = communication.ReceiveMessageWithSession(&buffer, key, session2)
	if err == nil {
		t.Fatal("Expected error when receiving with wrong session, but got none")
	}
}

// TestResetMessageHistory teste la réinitialisation de l'historique
func TestResetMessageHistory(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Reset test"
	sessionID := generateUniqueSessionID("test-reset")
	var buffer bytes.Buffer

	// Envoyer un message
	err := communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Recevoir le message
	_, err = communication.ReceiveMessageWithSession(&buffer, key, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Réinitialiser l'historique
	communication.ResetMessageHistory()

	// Vérifier que l'historique a été réinitialisé
	stats := communication.GetMessageHistoryStats()
	if totalSessions, ok := stats["total_sessions"].(int); ok && totalSessions != 0 {
		t.Errorf("Expected 0 sessions after reset, got %d", totalSessions)
	}
}

// TestValidateMessageIntegrity teste la validation de l'intégrité des messages
func TestValidateMessageIntegrity(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Validation test"
	sessionID := generateUniqueSessionID("test-validate")
	var buffer bytes.Buffer

	// Envoyer un message valide
	err := communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Obtenir les données chiffrées
	encryptedData := buffer.String()

	// Valider les données chiffrées
	err = communication.ValidateMessageIntegrity(encryptedData)
	if err != nil {
		t.Fatalf("Valid encrypted data failed validation: %v", err)
	}

	// Tester avec des données invalides
	err = communication.ValidateMessageIntegrity("")
	if err == nil {
		t.Fatal("Expected error for empty encrypted data")
	}

	err = communication.ValidateMessageIntegrity("invalid")
	if err == nil {
		t.Fatal("Expected error for invalid encrypted data")
	}
}

// TestMessageOverhead teste l'estimation de l'overhead des messages
func TestMessageOverhead(t *testing.T) {
	messageSize := 100
	overhead := communication.EstimateMessageOverhead(messageSize)

	if overhead <= 0 {
		t.Errorf("Expected positive overhead, got %d", overhead)
	}

	// L'overhead devrait être significatif mais raisonnable
	if overhead > messageSize*10 {
		t.Errorf("Overhead seems too large: %d for message size %d", overhead, messageSize)
	}
}

// TestSendMessageWithTimeout teste l'envoi avec timeout
func TestSendMessageWithTimeout(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Timeout test"
	sessionID := generateUniqueSessionID("test-timeout")

	var buffer bytes.Buffer

	// Test avec timeout normal - essayer de recevoir d'un buffer vide
	_, err := communication.ReceiveMessageWithTimeoutAndSession(&buffer, key, 100*time.Millisecond, sessionID)
	if err == nil {
		t.Fatal("Expected timeout error when no message is available")
	}

	// Envoyer un message puis le recevoir avec timeout
	err = communication.SendMessageWithSession(&buffer, testMessage, key, 1, 0, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	receivedMessage, err := communication.ReceiveMessageWithTimeoutAndSession(&buffer, key, 1*time.Second, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message with timeout: %v", err)
	}

	if receivedMessage != testMessage {
		t.Errorf("Expected message %q, got %q", testMessage, receivedMessage)
	}
}

// TestMessageWithRetry teste l'envoi avec retry
func TestMessageWithRetry(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Retry test"
	sessionID := generateUniqueSessionID("test-retry")
	var buffer bytes.Buffer

	// Test avec retry (devrait réussir du premier coup)
	err := communication.SendMessageWithRetryAndSession(&buffer, testMessage, key, 1, 0, 3, sessionID)
	if err != nil {
		t.Fatalf("Failed to send message with retry: %v", err)
	}

	// Recevoir le message
	receivedMessage, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	if receivedMessage != testMessage {
		t.Errorf("Expected message %q, got %q", testMessage, receivedMessage)
	}
}

// TestConcurrentMessages teste l'envoi concurrent de messages avec isolation totale
func TestConcurrentMessages(t *testing.T) {
	// Réinitialiser l'historique avant le test
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)

	// Utiliser des sessions complètement isolées pour chaque goroutine
	messages := []string{"msg1", "msg2", "msg3", "msg4", "msg5"}

	results := make(chan error, len(messages))

	for i, msg := range messages {
		go func(index int, message string) {
			var buffer bytes.Buffer
			sessionID := generateUniqueSessionID(fmt.Sprintf("concurrent-%d", index))

			// Envoyer avec une séquence unique
			err := communication.SendMessageWithSession(&buffer, message, key, uint64(index+10000), 0, sessionID)
			if err != nil {
				results <- err
				return
			}

			// Recevoir avec la même session
			received, err := communication.ReceiveMessageWithSession(&buffer, key, sessionID)
			if err != nil {
				results <- err
				return
			}

			if received != message {
				results <- fmt.Errorf("message mismatch: expected %q, got %q", message, received)
				return
			}

			results <- nil
		}(i, msg)
	}

	// Attendre tous les résultats
	for i := 0; i < len(messages); i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("Concurrent message test failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent message results")
		}
	}
}

// BenchmarkSendReceive benchmark pour l'envoi/réception avec sessions uniques
func BenchmarkSendReceive(b *testing.B) {
	// Réinitialiser l'historique avant le benchmark
	communication.ResetMessageHistory()

	key, _ := communication.GenerateRandomKey(32)
	testMessage := "Benchmark test message"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buffer bytes.Buffer

		// Utiliser une session unique pour éviter les conflits de replay
		sessionID := generateUniqueSessionID(fmt.Sprintf("bench-%d", i))

		// Envoyer avec une séquence unique
		err := communication.SendMessageWithSession(&buffer, testMessage, key, uint64(i+100000), 0, sessionID)
		if err != nil {
			b.Fatalf("Failed to send: %v", err)
		}

		// Recevoir
		_, err = communication.ReceiveMessageWithSession(&buffer, key, sessionID)
		if err != nil {
			b.Fatalf("Failed to receive: %v", err)
		}
	}
}
