package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

func main() {
	// Générer la paire de clés Ed25519 du serveur (pour signer le handshake).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Erreur lors de la génération des clés Ed25519 : %v", err)
	}
	log.Printf("Clé publique du serveur : %x", pubKey)

	// Démarrer le serveur TCP sur le port 8080.
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Erreur lors de l'écoute sur le port 8080 : %v", err)
	}
	defer ln.Close()
	log.Println("Serveur démarré sur le port 8080")

	// Accepter et gérer les connexions entrantes.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Erreur lors de l'acceptation d'une connexion : %v", err)
			continue
		}
		log.Printf("Nouvelle connexion de %v", conn.RemoteAddr())
		go handleConnection(conn, privKey)
	}
}

func handleConnection(conn net.Conn, privKey ed25519.PrivateKey) {
	defer conn.Close()

	// Établir une session sécurisée côté serveur.
	session, err := communication.NewServerSessionWithHandshake(conn, privKey)
	if err != nil {
		log.Printf("Erreur lors du handshake et de l'établissement de la session : %v", err)
		return
	}
	log.Printf("Session sécurisée établie avec %v", conn.RemoteAddr())

	// Boucle de traitement des messages : réception, affichage et réponse (echo).
	for {
		msg, err := session.ReceiveSecureMessage()
		if err != nil {
			log.Printf("Erreur lors de la réception d'un message : %v", err)
			break
		}
		log.Printf("Message reçu : %s", msg)

		// Répondre par un simple echo.
		reply := "Echo: " + msg
		if err := session.SendSecureMessage(reply, 1, 60); err != nil {
			log.Printf("Erreur lors de l'envoi de la réponse : %v", err)
			break
		}
	}
}
