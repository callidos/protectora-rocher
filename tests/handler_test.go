package tests

import (
	"bytes"
	"protectora-rocher/pkg/communication"
	"strings"
	"testing"
	"time"
)

func TestHandleConnection(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Simuler l'entrée du nom d'utilisateur suivie de la commande "exit"
	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("exit\n")

	// Lance la gestion de la connexion dans une goroutine pour ne pas bloquer le test
	go communication.HandleConnection(mockConn, sharedKey)

	// Attendre un peu avant de vérifier que le message de bienvenue a été envoyé
	// Le délai peut être ajusté en fonction de la performance du système
	time.Sleep(1 * time.Second)

	// Vérification de la présence d'un message de bienvenue dans la sortie du buffer
	output := mockConn.Buffer.String()
	t.Logf("Output buffer: %s", output)

	// Séparer le message chiffré et l'HMAC (attendu sous la forme chiffrée|hmac)
	parts := strings.SplitN(output, "|", 2)
	if len(parts) < 2 {
		t.Fatalf("Le message reçu est mal formé : %s", output)
	}

	// Le message chiffré et l'HMAC
	encryptedMessage := parts[0]
	receivedHMAC := strings.TrimSpace(parts[1]) // Trimming potential spaces

	// Affichage pour le débogage
	t.Logf("Encrypted Message: %s", encryptedMessage)
	t.Logf("Received HMAC: %s", receivedHMAC)

	// Vérification du HMAC
	expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
	t.Logf("Expected HMAC: %s", expectedHMAC)

	// Comparaison byte par byte des HMACs pour voir si des différences invisibles existent
	// Removing extra spaces before comparison
	if !bytes.Equal([]byte(strings.TrimSpace(receivedHMAC)), []byte(strings.TrimSpace(expectedHMAC))) {
		t.Fatalf("HMAC invalide, le message est corrompu. Attendu: %s, Reçu: %s", expectedHMAC, receivedHMAC)
	}

	// Déchiffrement du message pour vérification
	decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		t.Fatalf("Erreur lors du déchiffrement du message de bienvenue : %v", err)
	}

	expectedWelcomeMessage := "Bienvenue testuser sur le serveur sécurisé."
	if string(decryptedMessage) != expectedWelcomeMessage {
		t.Errorf("Le message de bienvenue attendu n'a pas été reçu. Reçu : %s", decryptedMessage)
	}

	// Fermeture de la connexion après le test
	if err := mockConn.Close(); err != nil {
		t.Fatalf("Erreur lors de la fermeture de la connexion : %v", err)
	}
}

// Test du traitement de message avec succès
func TestProcessIncomingMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Simuler un message encrypté
	message := "Hello, World!"
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmac + "\n")

	communication.HandleConnection(mockConn, sharedKey)
}

// Test du rejet des messages corrompus
func TestRejectCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Simuler un message corrompu
	mockConn.Buffer.WriteString("données corrompues|mauvaisHMAC\n")

	communication.HandleConnection(mockConn, sharedKey)
}
