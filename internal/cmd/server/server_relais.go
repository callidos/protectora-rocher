package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"

	"protectora-rocher/pkg/communication"
)

func main() {
	// Générer la paire de clés Ed25519 du serveur (utilisée pour signer le handshake).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Erreur lors de la génération de la clé Ed25519 : %v", err)
	}
	log.Printf("Clé publique du serveur : %x", pubKey)

	// Démarrer le serveur sur le port 8080.
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Erreur lors de l'écoute : %v", err)
	}
	defer listener.Close()
	log.Println("Serveur démarré sur le port 8080")

	// Accepter et gérer les connexions entrantes.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Erreur lors de l'acceptation de la connexion : %v", err)
			continue
		}
		log.Printf("Nouvelle connexion de %s", conn.RemoteAddr())
		go handleClient(conn, privKey)
	}
}

// handleClient réalise le handshake côté serveur et échange ensuite des messages.
func handleClient(conn net.Conn, privKey ed25519.PrivateKey) {
	defer conn.Close()

	session, err := communication.NewServerSessionWithHandshake(conn, privKey)
	if err != nil {
		log.Printf("Erreur lors du handshake avec %s : %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("Handshake réussi avec %s", conn.RemoteAddr())

	// Boucle de réception et réponse aux messages.
	for {
		msg, err := session.ReceiveSecureMessage()
		if err != nil {
			log.Printf("Erreur lors de la réception du message depuis %s : %v", conn.RemoteAddr(), err)
			break
		}
		log.Printf("Message reçu de %s : %s", conn.RemoteAddr(), msg)

		// Réponse d'écho.
		reply := "Echo: " + msg
		if err := session.SendSecureMessage(reply, 1, 60); err != nil {
			log.Printf("Erreur lors de l'envoi du message à %s : %v", conn.RemoteAddr(), err)
			break
		}
	}
}
