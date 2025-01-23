package tests

import (
	"bytes"
	"net"
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

	// Déclencher la goroutine pour gérer la connexion
	doneChan := make(chan bool)
	go func() {
		communication.HandleConnection(mockConn, sharedKey) // Correction ici
		doneChan <- true
	}()

	// Timeout si la goroutine prend trop de temps
	select {
	case <-doneChan:
		// Une fois la goroutine terminée, vérifier le buffer de la connexion mockée
		output := mockConn.Buffer.String()
		t.Logf("Output buffer: %s", output)

		// Analyse de l'accusé de réception et des messages
		parts := strings.SplitN(output, "|", 2)
		if len(parts) < 2 {
			t.Fatalf("Le message reçu est mal formé : %s", output)
		}

		encryptedMessage := parts[0]
		receivedHMAC := strings.TrimSpace(parts[1])

		expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)

		if !bytes.Equal([]byte(strings.TrimSpace(receivedHMAC)), []byte(strings.TrimSpace(expectedHMAC))) {
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

		// Fermer la connexion
		if err := mockConn.Close(); err != nil {
			t.Fatalf("Erreur lors de la fermeture de la connexion : %v", err)
		}
	case <-time.After(5 * time.Second): // Timeout si la goroutine prend trop de temps
		t.Fatal("Le test a dépassé le délai d'attente.")
	}
}

// Test du traitement d'un message reçu correctement
func TestProcessIncomingMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// 1) Simuler le username
	mockConn.Buffer.WriteString("testuser\n")

	// 2) Simuler un message chiffré
	message := "Message de test"
	encryptedMessage, _ := communication.EncryptAESGCM([]byte(message), sharedKey)
	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
	mockConn.Buffer.WriteString(encryptedMessage + "|" + hmac + "\n")

	// 3) Fin de session
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	// 4) Exécuter la gestion de la connexion
	go communication.HandleConnection(mockConn, sharedKey)

	// 5) Attendre un peu pour laisser le temps au serveur de traiter
	time.Sleep(1 * time.Second) // Attente d'un court moment

	// 6) Analyser la sortie
	output := mockConn.Buffer.String()
	t.Logf("Output buffer after processing: %s", output)

	// Vérifier qu'on a au moins une ligne contenant l'ACK en clair (après déchiffrement).
	if !containsDecryptedAck(output, "Message reçu avec succès.", sharedKey) {
		t.Errorf("L'accusé de réception du message n'a pas été reçu")
	}
}

// containsDecryptedAck parcourt chaque ligne, la sépare en encrypted|hmac, déchiffre et compare.
func containsDecryptedAck(fullOutput string, expectedAck string, sharedKey []byte) bool {
	lines := strings.Split(strings.TrimSpace(fullOutput), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		encrypted := parts[0]
		receivedHMAC := parts[1]

		// Vérifie l’intégrité
		expectedHMAC := communication.GenerateHMAC(encrypted, sharedKey)
		if expectedHMAC != strings.TrimSpace(receivedHMAC) {
			continue
		}

		// Déchiffre
		decrypted, err := communication.DecryptAESGCM(encrypted, sharedKey)
		if err != nil {
			continue
		}

		// Compare avec le texte attendu
		if string(decrypted) == expectedAck {
			return true
		}
	}
	return false
}

// Test du rejet de messages corrompus
func TestRejectCorruptedMessage(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("message-corrompu|mauvaisHMAC\n")
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, sharedKey)

	// Attendre l'envoi de l'accusé de réception
	time.Sleep(1 * time.Second)

	output := mockConn.Buffer.String()
	t.Logf("Output buffer for corrupted message: %s", output)

	if strings.Contains(output, "Message reçu avec succès.") {
		t.Errorf("Le message corrompu aurait dû être rejeté")
	}
}

// Test de gestion d'une connexion interrompue
func TestHandleConnectionWithError(t *testing.T) {
	listener, _ := net.Listen("tcp", "localhost:8081")
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		conn.Close() // Simule une coupure de connexion immédiate
	}()

	conn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		t.Fatalf("Erreur de connexion au serveur : %v", err)
	}

	sharedKey := []byte("thisisaverysecurekey!")

	// Appel sans WaitGroup
	communication.HandleConnection(conn, sharedKey)

	t.Log("Test de gestion des connexions avec interruption")
}

// Test de la durée de session
func TestHandleConnectionSessionDuration(t *testing.T) {
	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	mockConn.Buffer.WriteString("testuser\n")
	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, sharedKey)

	// Attendre un peu avant de vérifier le résultat
	time.Sleep(3 * time.Second)

	if mockConn.Buffer.Len() == 0 {
		t.Errorf("Aucun message échangé pendant la session")
	}
}

// Test de réception de plusieurs messages en séquence
func TestHandleMultipleMessages(t *testing.T) {
	// Réinitialisation de l'historique des messages avant chaque test
	communication.ResetMessageHistory()

	mockConn := &MockConnection{}
	sharedKey := []byte("thisisaverysecurekey!")

	// Initialisation des messages
	messages := []string{"Message 1", "Message 2", "Message 3"}
	for _, msg := range messages {
		encryptedMessage, _ := communication.EncryptAESGCM([]byte(msg), sharedKey)
		hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
		mockConn.Buffer.WriteString(encryptedMessage + "|" + hmac + "\n")
	}

	mockConn.Buffer.WriteString("FIN_SESSION\n")

	go communication.HandleConnection(mockConn, sharedKey)

	// Attendre que la fonction de gestion de connexion ait terminé
	time.Sleep(3 * time.Second)

	// Log complet du buffer pour mieux analyser
	output := mockConn.Buffer.String()
	t.Logf("Output buffer after multiple messages: %s", output)

	// Vérifier chaque accusé de réception pour les messages
	for _, msg := range messages {
		expectedAck := "Message reçu avec succès."
		encMsg, _ := communication.EncryptAESGCM([]byte(expectedAck), sharedKey)
		if !strings.Contains(output, encMsg) {
			t.Errorf("L'accusé de réception pour '%s' n'a pas été reçu", msg)
		} else {
			t.Logf("Accusé de réception trouvé pour '%s': %s", msg, encMsg)
		}
	}
}
