package tests

import (
	"protectora-rocher/pkg/communication"
	"testing"
)

// Test de la génération de paire de clés Ed25519
func TestGenerateEd25519KeyPair(t *testing.T) {
	publicKey, privateKey, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Erreur lors de la génération de la clé Ed25519 : %v", err)
	}

	if len(publicKey) != 32 || len(privateKey) != 64 {
		t.Errorf("Les longueurs des clés générées sont incorrectes")
	}
}

// Test de l'échange de clés sécurisé
func TestPerformAuthenticatedKeyExchange(t *testing.T) {
	mockConn := &MockConnection{}
	publicKey, privateKey, _ := communication.GenerateEd25519KeyPair()

	communication.ResetKeyExchangeState()

	_, err := communication.PerformAuthenticatedKeyExchange(mockConn, privateKey, publicKey)
	if err != nil {
		t.Fatalf("Erreur lors de l'échange de clés sécurisé : %v", err)
	}
}

// Test de la rotation des clés après l'expiration de l'intervalle de temps
func TestKeyRotation(t *testing.T) {
	mockConn := &MockConnection{}
	publicKey, privateKey, _ := communication.GenerateEd25519KeyPair()

	communication.ResetKeyExchangeState()

	// Effectuer un premier échange de clés
	_, err := communication.PerformAuthenticatedKeyExchange(mockConn, privateKey, publicKey)
	if err != nil {
		t.Fatalf("Erreur lors de l'échange initial de clés sécurisé : %v", err)
	}

	// Simuler une expiration du délai de rotation
	communication.ResetKeyExchangeState()

	_, err = communication.PerformAuthenticatedKeyExchange(mockConn, privateKey, publicKey)
	if err != nil {
		t.Fatalf("Erreur lors de la rotation des clés : %v", err)
	}
}
