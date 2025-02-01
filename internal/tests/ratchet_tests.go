// Fichier : internal/tests/double_ratchet_integration_test.go
package tests

import (
	"crypto/rand"
	"testing"

	"protectora-rocher/pkg/communication"
)

// TestIndependentEvolution simule l'évolution indépendante des chaînes entre deux parties (client et serveur)
// et vérifie que la clé de message dérivée est identique pour le chiffrement et le déchiffrement.
func TestIndependentEvolution(t *testing.T) {
	// Génération d'une clé de session aléatoire (32 octets).
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("Erreur de génération de la session key: %v", err)
	}

	// Génération des paires DH pour le client et le serveur.
	clientDH, err := communication.GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Erreur de génération de la paire DH côté client: %v", err)
	}
	serverDH, err := communication.GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Erreur de génération de la paire DH côté serveur: %v", err)
	}

	// Initialisation du double ratchet côté client :
	// Le client utilise sa paire DH et la clé publique du serveur.
	clientDR, err := communication.InitializeDoubleRatchet(sessionKey, clientDH, serverDH.Public)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet côté client: %v", err)
	}

	// Initialisation du double ratchet côté serveur :
	// Le serveur utilise sa paire DH et la clé publique du client.
	serverDR, err := communication.InitializeDoubleRatchet(sessionKey, serverDH, clientDH.Public)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet côté serveur: %v", err)
	}
	// Pour synchroniser les rôles, le serveur doit inverser ses chaînes :
	serverDR.SendingChain, serverDR.ReceivingChain = serverDR.ReceivingChain, serverDR.SendingChain

	// Simuler l'envoi d'un message par le client.
	message := "Hello, independent world!"
	clientMsgKey, err := clientDR.RatchetEncrypt()
	if err != nil {
		t.Fatalf("Erreur lors de RatchetEncrypt côté client: %v", err)
	}

	// Le client chiffre le message avec la clé dérivée.
	ciphertext, err := communication.EncryptAESGCM([]byte(message), clientMsgKey)
	if err != nil {
		t.Fatalf("Erreur lors de EncryptAESGCM: %v", err)
	}

	// Simuler la réception du message par le serveur.
	serverMsgKey, err := serverDR.RatchetDecrypt()
	if err != nil {
		t.Fatalf("Erreur lors de RatchetDecrypt côté serveur: %v", err)
	}

	plaintext, err := communication.DecryptAESGCM(ciphertext, serverMsgKey)
	if err != nil {
		t.Fatalf("Erreur lors de DecryptAESGCM: %v", err)
	}

	if string(plaintext) != message {
		t.Errorf("Message incorrect: attendu %s, obtenu %s", message, string(plaintext))
	}
}
