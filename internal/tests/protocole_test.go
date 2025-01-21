package tests

import (
	"protectora-rocher/pkg/communication"
	"strconv"
	"testing"
	"time"
)

// Test de l'envoi de messages sécurisés
func TestSendMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")
	sequenceNumber := uint64(1)
	message := "Test message"

	err := communication.SendMessage(mockConn, message, sharedKey, sequenceNumber)
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

	// Générer un timestamp "valide" pour éviter l'erreur d'expiration
	timestamp := time.Now().Unix()

	formattedMessage := "1|" + strconv.FormatInt(timestamp, 10) + "|" + message
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(formattedMessage), sharedKey)
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
	// On réinitialise l'historique pour éviter la pollution d'autres tests
	communication.ResetMessageHistory()

	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Générer un timestamp valide
	timestamp := time.Now().Unix()

	// Construire le message (même sequenceNumber "1")
	message := "1|" + strconv.FormatInt(timestamp, 10) + "|Replay attack test"

	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmacVal := communication.GenerateHMAC(encryptedMessage, sharedKey)

	// 1) Premier envoi : le message doit être accepté
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmacVal + "\n")
	_, err := communication.ReceiveMessage(mockConn, sharedKey)
	if err != nil {
		t.Fatalf("Erreur inattendue lors de la première réception : %v", err)
	}

	// Vider le buffer pour la deuxième réception (facultatif)
	mockConn.Buffer.Reset()

	// 2) Second envoi (même message) : le message doit être rejeté (rejeu)
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
