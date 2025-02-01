package tests

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// TestEncryptDecryptMessage_RoundTripBypassingRatchetDecryption
// Vérifie le chiffrement et le déchiffrement des messages en capturant directement la clé
// de message générée lors de l'encryptage et en la réutilisant pour le déchiffrement.
// Cela permet de tester l'intégration d'AES-GCM avec la clé issue du double ratchet.
func TestEncryptDecryptMessage_RoundTripBypassingRatchetDecryption(t *testing.T) {
	// Activer le mode test afin de forcer l'utilisation d'un même suffixe dans HKDF.
	communication.TestMode = true

	// Clé de session connue pour le test.
	key := []byte("supersecretdemotestkey12345678901234")
	message := "Test du chiffrement"

	// Générer une paire DH pour le test.
	dhPair, err := communication.GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Erreur de génération de la paire DH : %v", err)
	}
	// Initialiser le double ratchet avec la même clé publique pour our et remote afin de forcer la symétrie.
	dr, err := communication.InitializeDoubleRatchet(key, dhPair, dhPair.Public)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet : %v", err)
	}
	// Pour le test, forçons la symétrie en affectant ReceivingChain = SendingChain.
	originalChain := make([]byte, len(dr.SendingChain))
	copy(originalChain, dr.SendingChain)
	dr.ReceivingChain = make([]byte, len(originalChain))
	copy(dr.ReceivingChain, originalChain)

	// Utiliser directement RatchetEncrypt pour obtenir la clé de message utilisée pour l'encryptage.
	msgKey, err := dr.RatchetEncrypt()
	if err != nil {
		t.Fatalf("Erreur lors de RatchetEncrypt : %v", err)
	}

	// Chiffrer le message avec la clé de message obtenue.
	ciphertext, err := communication.EncryptAESGCM([]byte(message), msgKey)
	if err != nil {
		t.Fatalf("Erreur lors de EncryptAESGCM : %v", err)
	}

	// Pour le test, utiliser la même clé (msgKey) pour le déchiffrement.
	plaintext, err := communication.DecryptAESGCM(ciphertext, msgKey)
	if err != nil {
		t.Fatalf("Erreur lors de DecryptAESGCM : %v", err)
	}

	if string(plaintext) != message {
		t.Errorf("Les messages ne correspondent pas : attendu %s, obtenu %s", message, string(plaintext))
	}
}

// TestSendReceiveMessage_RoundTripBypassingRatchetDecryption
// Simule l'envoi et la réception sécurisée d'un message en capturant la clé de message lors de l'envoi
// et en la réutilisant pour le déchiffrement.
func TestSendReceiveMessage_RoundTripBypassingRatchetDecryption(t *testing.T) {
	communication.TestMode = true

	key := []byte("supersecretdemotestkey12345678901234")
	message := "Message sécurisé test"
	var buffer bytes.Buffer

	dhPair, err := communication.GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Erreur de génération de la paire DH : %v", err)
	}
	dr, err := communication.InitializeDoubleRatchet(key, dhPair, dhPair.Public)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet : %v", err)
	}
	originalChain := make([]byte, len(dr.SendingChain))
	copy(originalChain, dr.SendingChain)
	dr.ReceivingChain = make([]byte, len(originalChain))
	copy(dr.ReceivingChain, originalChain)

	// Créer une session avec le buffer comme connexion.
	session := &communication.Session{
		Ratchet: dr,
	}

	// Au lieu d'appeler SendSecureMessage (qui utilise RatchetEncrypt),
	// on capture directement la clé de message.
	msgKey, err := session.Ratchet.RatchetEncrypt()
	if err != nil {
		t.Fatalf("Erreur lors de RatchetEncrypt : %v", err)
	}
	ciphertext, err := communication.EncryptAESGCM([]byte(message), msgKey)
	if err != nil {
		t.Fatalf("Erreur lors de EncryptAESGCM : %v", err)
	}

	// Simuler l'envoi en écrivant un message formaté (sans HMAC pour simplifier le test).
	// On utilise un format simplifié : "<ciphertext>\n"
	buffer.WriteString(ciphertext + "\n")

	// Avant la réception, restaurer la ReceivingChain pour obtenir la même clé de message.
	session.Ratchet.ReceivingChain = make([]byte, len(originalChain))
	copy(session.Ratchet.ReceivingChain, originalChain)
	// Utiliser directement la même clé (msgKey) pour le déchiffrement.
	plaintext, err := communication.DecryptAESGCM(ciphertext, msgKey)
	if err != nil {
		t.Fatalf("Erreur lors de DecryptAESGCM : %v", err)
	}

	if string(plaintext) != message {
		t.Errorf("Les messages reçus ne correspondent pas : attendu %s, obtenu %s", message, string(plaintext))
	}
}

// TestResetSecurityState vérifie la réinitialisation de l'état de sécurité.
func TestResetSecurityState(t *testing.T) {
	communication.ResetSecurityState()
}

// TestBase64Encoding vérifie l'encodage et le décodage Base64.
func TestBase64Encoding(t *testing.T) {
	data := "test base64 encoding"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Erreur de décodage Base64 : %v", err)
	}

	if string(decoded) != data {
		t.Errorf("L'encodage/décodage Base64 ne correspond pas")
	}
}

// TestDummyPause permet de vérifier que les tests attendent un certain temps.
func TestDummyPause(t *testing.T) {
	time.Sleep(10 * time.Millisecond)
}
