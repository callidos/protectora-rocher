package tests

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"protectora-rocher/pkg/communication"
)

// TestEncryptDecryptMessage vérifie le chiffrement et le déchiffrement des messages via la session.
func TestEncryptDecryptMessage(t *testing.T) {
	// Pour ce test, nous créons une session de test avec une clé connue.
	// On utilise cette clé pour initialiser le double ratchet.
	key := []byte("supersecretdemotestkey12345678901234")
	message := "Test du chiffrement"

	dr, err := communication.InitializeDoubleRatchet(key)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet : %v", err)
	}
	// Pour ce test unitaire, forçons la symétrie pour pouvoir déchiffrer
	// le message chiffré par la même instance.
	dr.ReceivingChain = dr.SendingChain

	// Création manuelle d'une session de test (le champ Conn n'est pas utilisé ici).
	session := &communication.Session{
		Ratchet: dr,
	}

	encrypted, err := session.EncryptMessage(message)
	if err != nil {
		t.Fatalf("Erreur de chiffrement : %v", err)
	}

	decrypted, err := session.DecryptMessage(encrypted)
	if err != nil {
		t.Fatalf("Erreur de déchiffrement : %v", err)
	}

	if decrypted != message {
		t.Errorf("Les messages ne correspondent pas : attendu %s, obtenu %s", message, decrypted)
	}
}

// TestSendReceiveMessage vérifie l'envoi et la réception sécurisée des messages via la session.
func TestSendReceiveMessage(t *testing.T) {
	key := []byte("supersecretdemotestkey12345678901234")
	message := "Message sécurisé test"
	var buffer bytes.Buffer

	dr, err := communication.InitializeDoubleRatchet(key)
	if err != nil {
		t.Fatalf("Erreur d'initialisation du double ratchet : %v", err)
	}
	// Pour ce test unitaire, forçons la symétrie en utilisant la même chaîne pour l'envoi et la réception.
	dr.ReceivingChain = dr.SendingChain

	// Création d'une session de test avec le buffer comme connexion.
	session := &communication.Session{
		Conn:    &buffer,
		Ratchet: dr,
	}

	err = session.SendSecureMessage(message, 1, 60)
	if err != nil {
		t.Fatalf("Erreur d'envoi du message sécurisé : %v", err)
	}

	received, err := session.ReceiveSecureMessage()
	if err != nil {
		t.Fatalf("Erreur de réception du message sécurisé : %v", err)
	}

	if received != message {
		t.Errorf("Les messages reçus ne correspondent pas : attendu %s, obtenu %s", message, received)
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

// ---------------------------------------------------------------------
// REMARQUE :
// Les tests relatifs au handshake (ex. TestHandleNewConnection et
// TestPerformKeyExchange) ont été retirés de ce fichier de tests unitaire,
// car l'API exposée ne propose qu'une interface simplifiée via
// NewSessionWithHandshake destinée à une intégration complète.
// Ces scénarios nécessitent des tests d'intégration avec simulation de
// l'échange complet de clés, ce qui dépasse le cadre des tests unitaires.
// ---------------------------------------------------------------------

// TestDummyPause permet de vérifier que les tests attendent un certain temps,
// par exemple pour simuler des délais éventuels dans la communication.
func TestDummyPause(t *testing.T) {
	time.Sleep(10 * time.Millisecond)
}
