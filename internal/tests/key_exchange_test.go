package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"protectora-rocher/pkg/communication"
	"testing"
)

func TestFullKyberExchange(t *testing.T) {
	// Génération de la paire de clés Ed25519 pour le serveur.
	_, serverPrivEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Échec génération clés serveur : %v", err)
	}

	// Génération de la paire de clés Ed25519 pour le client.
	_, clientPrivEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Échec génération clés client : %v", err)
	}

	// Création d'une connexion en mémoire pour simuler une communication bidirectionnelle.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Lancement du handshake côté serveur.
	serverResultChan, err := communication.ServerPerformKeyExchange(serverConn, serverPrivEd)
	if err != nil {
		t.Fatalf("Échec initialisation serveur : %v", err)
	}

	// Lancement du handshake côté client.
	clientResultChan, err := communication.ClientPerformKeyExchange(clientConn, clientPrivEd)
	if err != nil {
		t.Fatalf("Échec initialisation client : %v", err)
	}

	// Récupération du résultat du handshake côté serveur.
	serverResult := <-serverResultChan
	if serverResult.Err != nil {
		t.Fatalf("Erreur côté serveur : %v", serverResult.Err)
	}

	// Récupération du résultat du handshake côté client.
	clientResult := <-clientResultChan
	if clientResult.Err != nil {
		t.Fatalf("Erreur côté client : %v", clientResult.Err)
	}

	// Vérification que les clés de session dérivées sont identiques.
	if !bytes.Equal(serverResult.Key[:], clientResult.Key[:]) {
		t.Fatalf("Clés différentes\nServeur: %x\nClient: %x", serverResult.Key, clientResult.Key)
	}
}
