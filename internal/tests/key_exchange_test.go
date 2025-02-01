package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"protectora-rocher/pkg/communication"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
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
func simulateClient(conn net.Conn, serverPubEd25519 ed25519.PublicKey) ([]byte, error) {
	pkBytes, err := readBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("échec lecture clé publique: %v", err)
	}

	signature, err := readBytes(conn)
	if err != nil {
		return nil, fmt.Errorf("échec lecture signature: %v", err)
	}

	if !ed25519.Verify(serverPubEd25519, pkBytes, signature) {
		return nil, fmt.Errorf("signature invalide")
	}

	var serverPubKyber kyber768.PublicKey
	serverPubKyber.Unpack(pkBytes)

	ciphertext := make([]byte, kyber768.CiphertextSize)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	serverPubKyber.EncapsulateTo(ciphertext, sharedSecret, nil)

	sessionKey := communication.DeriveSessionKey(sharedSecret)
	communication.Memzero(sharedSecret)

	if err := sendBytes(conn, ciphertext); err != nil {
		return nil, fmt.Errorf("échec envoi ciphertext: %v", err)
	}

	return sessionKey[:], nil
}

func readBytes(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := conn.Read(lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length > 65536 {
		return nil, fmt.Errorf("taille excessive")
	}

	data := make([]byte, length)
	if _, err := conn.Read(data); err != nil {
		return nil, err
	}

	return data, nil
}

func sendBytes(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}

	if _, err := conn.Write(data); err != nil {
		return err
	}

	return nil
}
