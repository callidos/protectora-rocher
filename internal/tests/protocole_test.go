package tests

import (
	"strconv"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// Test de l'envoi de messages sécurisés avec différentes durées
func TestSendMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	sequenceNumber := uint64(1)
	message := "Test message"

	testCases := []struct {
		duration   int
		shouldFail bool
	}{
		{0, false},  // Message permanent
		{60, false}, // Message temporaire (1 minute)
		{-10, true}, // Durée négative (devrait échouer)
	}

	for _, tc := range testCases {
		mockConn.Buffer.Reset()
		err := communication.SendMessage(mockConn, message, sharedKey, sequenceNumber, tc.duration)

		if tc.shouldFail {
			if err == nil {
				t.Errorf("L'envoi d'un message avec une durée invalide aurait dû échouer")
			}
		} else {
			if err != nil {
				t.Fatalf("Erreur lors de l'envoi du message : %v", err)
			}
			if mockConn.Buffer.String() == "" {
				t.Errorf("Aucun message envoyé via la connexion mockée")
			}
		}
	}
}

// Test de la réception de messages sécurisés valides
func TestReceiveMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	message := "Test message"
	timestamp := time.Now().Unix()
	duration := 60

	formattedMessage := "1|" + strconv.FormatInt(timestamp, 10) + "|" + strconv.Itoa(duration) + "|" + message
	encryptedMessage, err := communication.EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		t.Fatalf("Erreur lors du chiffrement : %v", err)
	}

	hmacVal := communication.GenerateHMAC(encryptedMessage, sharedKey)
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")

	receivedMessage, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err != nil {
		t.Fatalf("Erreur lors de la réception du message : %v", err)
	}

	if receivedMessage != message {
		t.Errorf("Le message reçu ne correspond pas à l'original. Attendu=%q, Reçu=%q", message, receivedMessage)
	}
}

// Test de détection des attaques par rejeu
func TestReplayAttack(t *testing.T) {
	communication.ResetMessageHistory()
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	timestamp := time.Now().Unix()
	duration := 0

	message := "1|" + strconv.FormatInt(timestamp, 10) + "|" + strconv.Itoa(duration) + "|Replay attack test"
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmacVal := communication.GenerateHMAC(encryptedMessage, sharedKey)

	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err != nil {
		t.Fatalf("Erreur inattendue lors de la première réception : %v", err)
	}

	mockConn.Buffer.Reset()
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err = communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Le message en double aurait dû être rejeté en tant qu'attaque par rejeu")
	}
}

// Test du rejet des messages corrompus (mauvais HMAC)
func TestCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("message-corrompu|mauvaisHMAC\n")

	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Le message corrompu aurait dû être rejeté")
	}
}

// Test de la gestion des messages expirés
func TestExpiredMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	timestamp := time.Now().Unix() - 1000 // Message ancien
	duration := 500                       // Expiré

	message := "2|" + strconv.FormatInt(timestamp, 10) + "|" + strconv.Itoa(duration) + "|Expired message"
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmacVal := communication.GenerateHMAC(encryptedMessage, sharedKey)

	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Le message expiré aurait dû être rejeté")
	}
}

// Test de réception de message avec mauvais format
func TestMalformedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("malformed_message_without_hmac\n")

	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Un message mal formé aurait dû être rejeté")
	}
}

// Test de performance pour l'envoi et la réception de messages
func TestMessagePerformance(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	sequenceNumber := uint64(1)
	message := "Message de test de performance"

	start := time.Now()

	for i := 0; i < 1000; i++ {
		err := communication.SendMessage(mockConn, message, sharedKey, sequenceNumber, 0)
		if err != nil {
			t.Fatalf("Erreur lors de l'envoi du message : %v", err)
		}
	}

	duration := time.Since(start)
	t.Logf("Temps pris pour envoyer 1000 messages : %v", duration)
}
