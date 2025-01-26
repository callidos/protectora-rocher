package tests

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
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
	_, privKey, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clés Dilithium: %v", err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan bool)

	go func() {
		_, err := communication.PerformKeyExchange(server, privKey)
		if err != nil {
			t.Errorf("Erreur d'échange de clés côté serveur: %v", err)
		}
		done <- true
	}()

	select {
	case <-done:
		t.Log("Échange de clé terminé avec succès")
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout : l'échange de clé a pris trop de temps")
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
