package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"protectora-rocher/pkg/communication"
	"strings"
	"testing"
	"time"
)

// TestEncryptDecryptMessage vérifie le chiffrement et déchiffrement des messages.
func TestEncryptDecryptMessage(t *testing.T) {
	key := []byte("supersecretdemotestkey12345678901234")
	message := "Test du chiffrement"

	encrypted, err := communication.EncryptMessage(message, key)
	if err != nil {
		t.Fatalf("Erreur de chiffrement: %v", err)
	}

	decrypted, err := communication.DecryptMessage(encrypted, key)
	if err != nil {
		t.Fatalf("Erreur de déchiffrement: %v", err)
	}

	if decrypted != message {
		t.Errorf("Les messages ne correspondent pas: attendu %s, obtenu %s", message, decrypted)
	}
}

// TestSendReceiveMessage vérifie l'envoi et la réception sécurisée des messages.
func TestSendReceiveMessage(t *testing.T) {
	key := []byte("supersecretdemotestkey12345678901234")
	message := "Message sécurisé test"
	var buffer bytes.Buffer

	err := communication.SendSecureMessage(&buffer, message, key, 1, 60)
	if err != nil {
		t.Fatalf("Erreur d'envoi du message sécurisé: %v", err)
	}

	received, err := communication.ReceiveSecureMessage(&buffer, key)
	if err != nil {
		t.Fatalf("Erreur de réception du message sécurisé: %v", err)
	}

	if received != message {
		t.Errorf("Les messages reçus ne correspondent pas: attendu %s, obtenu %s", message, received)
	}
}

// TestHandleNewConnection vérifie la gestion des connexions sécurisées.
func TestHandleNewConnection(t *testing.T) {
	key := []byte("supersecretdemotestkey12345678901234")
	input := "testuser\nFIN_SESSION\n"
	reader := bytes.NewReader([]byte(input))
	var writer bytes.Buffer

	go communication.HandleNewConnection(reader, &writer, key)

	// Attendre un court instant pour permettre l'écriture dans le buffer
	time.Sleep(100 * time.Millisecond)

	output := writer.String()
	if output == "" {
		t.Errorf("Aucune sortie de la connexion")
	}

	t.Logf("Sortie obtenue: %q", output)

	// Le message est sous la forme: "encrypted_message|hmac_value"
	parts := strings.SplitN(strings.TrimSpace(output), "|", 2)
	if len(parts) != 2 {
		t.Fatalf("Format de sortie incorrect: %q", output)
	}

	encryptedMessage := parts[0]

	// Déchiffrement du message
	decryptedMessage, err := communication.DecryptMessage(encryptedMessage, key)
	if err != nil {
		t.Fatalf("Erreur de déchiffrement du message: %v", err)
	}

	expected := "Bienvenue testuser sur le serveur sécurisé."
	if decryptedMessage != expected {
		t.Errorf("Message déchiffré inattendu. Attendu %q, obtenu %q", expected, decryptedMessage)
	}
}

// TestPerformKeyExchange vérifie l'échange de clés sécurisé.
func TestPerformKeyExchange(t *testing.T) {
	// Génération de la clé privée Ed25519 (seulement la clé privée est nécessaire)
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur de génération de clé privée Ed25519: %v", err)
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

// TestBase64Encoding vérifie l'encodage et décodage base64
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
