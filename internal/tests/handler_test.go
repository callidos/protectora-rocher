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
	time.Sleep(1 * time.Second)

	// Vérification de la présence d'un message de bienvenue dans la sortie du buffer
	output := mockConn.Buffer.String()
	t.Logf("Output buffer: %s", output)

	// Séparer le message chiffré et l'HMAC (attendu sous la forme chiffrée|hmac)
	parts := strings.SplitN(output, "|", 2)
	if len(parts) < 2 {
		t.Fatalf("Le message reçu est mal formé : %s", output)
	}

	encryptedMessage := parts[0]
	receivedHMAC := strings.TrimSpace(parts[1]) // on enlève les espaces

	t.Logf("Encrypted Message: %s", encryptedMessage)
	t.Logf("Received HMAC: %s", receivedHMAC)

	// Vérification du HMAC
	expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
	t.Logf("Expected HMAC: %s", expectedHMAC)

	// Comparaison stricte
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

	// 1) Écrire la première ligne pour simuler le username
	mockConn.Buffer.WriteString("testuser\n")

	// 2) Simuler un message chiffré
	message := "Hello, World!"
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)

	// Le message va être la deuxième ligne, traitée comme le "receivedMessage"
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmac + "\n")

	// 3) Ajouter la commande "exit" (troisième ligne) pour clore la boucle
	mockConn.Buffer.WriteString("exit\n")

	// On lance l'handle
	communication.HandleConnection(mockConn, sharedKey)

	// Si nécessaire, on peut vérifier dans mockConn.Buffer l'ack envoyé par le serveur
	output := mockConn.Buffer.String()
	t.Logf("Output buffer after message processed: %s", output)
}

// Test du rejet des messages corrompus
func TestRejectCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// 1) Écrire la première ligne pour simuler le username
	mockConn.Buffer.WriteString("testuser\n")

	// 2) Simuler un message corrompu
	mockConn.Buffer.WriteString("données corrompues|mauvaisHMAC\n")

	// 3) Ajouter la commande "exit"
	mockConn.Buffer.WriteString("exit\n")

	// On lance l'handle
	communication.HandleConnection(mockConn, sharedKey)

	// Ici, on ne reçoit pas la confirmation de message puisqu'il est corrompu
	// mais on peut analyser le Buffer ou vérifier les logs si besoin.
	output := mockConn.Buffer.String()
	t.Logf("Output buffer for corrupted message: %s", output)
}
