package tests

import (
	"encoding/base64"
	"log"
	"net"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

func TestInitializeSession(t *testing.T) {
	err := communication.InitializeSession("persistent")
	if err != nil {
		t.Fatalf("Erreur d'initialisation de la session: %v", err)
	}
}

// TestEncryptDecryptMessage vérifie le chiffrement et déchiffrement des messages.
func TestEncryptDecryptMessage(t *testing.T) {
	key := []byte("examplekey123456examplekey123456")
	message := "Bienvenue testuser sur le serveur sécurisé."

	encryptedMessage, err := communication.EncryptMessage(message, key)
	if err != nil {
		t.Fatalf("Erreur de chiffrement du message: %v", err)
	}

	decryptedMessage, err := communication.DecryptMessage(encryptedMessage, key)
	if err != nil {
		t.Fatalf("Erreur de déchiffrement du message: %v", err)
	}

	expected := "Bienvenue testuser sur le serveur sécurisé."
	if decryptedMessage != expected {
		t.Errorf("Message déchiffré inattendu. Attendu %q, obtenu %q", expected, decryptedMessage)
	}
}

// TestSendReceiveSecureMessage vérifie l'envoi et la réception de messages sécurisés.
func TestSendReceiveSecureMessage(t *testing.T) {
	key := []byte("examplekey123456")
	message := "Message sécurisé"
	seqNum := uint64(1)
	duration := 10

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		err := communication.SendSecureMessage(server, message, key, seqNum, duration)
		if err != nil {
			t.Errorf("Erreur d'envoi de message sécurisé: %v", err)
		}
	}()

	receivedMessage, err := communication.ReceiveSecureMessage(client, key)
	if err != nil {
		t.Fatalf("Erreur de réception de message sécurisé: %v", err)
	}

	if receivedMessage != message {
		t.Errorf("Message reçu inattendu. Attendu %q, obtenu %q", message, receivedMessage)
	}
}

// TestPerformKeyExchange vérifie l'échange de clés sécurisé.
func TestPerformKeyExchange(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error)

	go func() {
		log.Println("Serveur: Démarrage de l'échange de clés")
		err := communication.PerformKeyExchange(server)
		if err != nil {
			log.Printf("Serveur: Échec de l'échange de clés: %v", err)
		}
		done <- err
	}()

	log.Println("Client: Démarrage de l'échange de clés")
	err := communication.PerformKeyExchange(client)
	if err != nil {
		t.Fatalf("Client: Échec de l'échange de clés: %v", err)
	}

	select {
	case serverErr := <-done:
		if serverErr != nil {
			t.Fatalf("Erreur d'échange de clés côté serveur: %v", serverErr)
		}
		t.Log("Échange de clé terminé avec succès")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout: l'échange de clé a pris trop de temps")
	}
}

// TestResetSecurityState vérifie la réinitialisation de l'état de sécurité.
func TestResetSecurityState(t *testing.T) {
	communication.ResetSecurityState()
}

// TestBase64Encoding vérifie l'encodage et décodage base64.
func TestBase64Encoding(t *testing.T) {
	data := "test base64 encoding"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Erreur de décodage Base64: %v", err)
	}

	if string(decoded) != data {
		t.Errorf("L'encodage/décodage Base64 ne correspond pas")
	}
}
