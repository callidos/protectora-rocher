package tests

import (
	"strconv"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// Test de l'envoi de messages sécurisés avec durée
func TestSendMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	sequenceNumber := uint64(1)
	message := "Test message"
	duration := 0 // Durée 0 pour un message permanent

	err := communication.SendMessage(mockConn, message, sharedKey, sequenceNumber, duration)
	if err != nil {
		t.Fatalf("Erreur lors de l'envoi du message : %v", err)
	}

	output := mockConn.Buffer.String()
	if output == "" {
		t.Errorf("Aucun message n'a été envoyé via la connexion mockée")
	}
}

// Test de la réception de messages sécurisés valides
func TestReceiveMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	message := "Test message"

	// Générer un timestamp valide et définir la durée
	timestamp := time.Now().Unix()
	duration := 0 // Message permanent

	// Construire le message avec le nouveau format : sequence|timestamp|durée|message
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

// Test de la détection d'une attaque par rejeu
func TestReplayAttack(t *testing.T) {
	communication.ResetMessageHistory()

	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Générer un timestamp valide et définir la durée
	timestamp := time.Now().Unix()
	duration := 0 // permanent

	// Construire le message avec les mêmes valeurs pour simuler un rejeu
	message := "1|" + strconv.FormatInt(timestamp, 10) + "|" + strconv.Itoa(duration) + "|Replay attack test"
	encryptedMessage, err := communication.EncryptAESGCM([]byte(message), sharedKey)
	if err != nil {
		t.Fatalf("Erreur lors du chiffrement initial : %v", err)
	}
	hmacVal := communication.GenerateHMAC(encryptedMessage, sharedKey)

	// 1) Premier envoi : le message doit être accepté
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err = communication.ReceiveMessage(mockConn, sharedKey)
	if err != nil {
		t.Fatalf("Erreur inattendue lors de la première réception : %v", err)
	}

	mockConn.Buffer.Reset()

	// 2) Second envoi (même message) : le message doit être rejeté comme rejeu
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err = communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Le message en double aurait dû être rejeté en tant qu'attaque par rejeu")
	}
}

// Test du rejet de messages corrompus
func TestCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Simuler un message corrompu (mauvais HMAC)
	mockConn.Buffer.WriteString("message-corrompu|mauvaisHMAC\n")

	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err == nil {
		t.Errorf("Le message corrompu aurait dû être rejeté")
	}
}
