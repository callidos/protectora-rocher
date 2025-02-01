package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"protectora-rocher/pkg/communication"
)

func main() {
	// Connexion au serveur sur localhost:8080.
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("Erreur de connexion : %v", err)
	}
	defer conn.Close()
	log.Println("Connecté au serveur sur localhost:8080")

	// Générer la paire de clés Ed25519 du client (pour signer le handshake).
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Erreur lors de la génération de la clé Ed25519 : %v", err)
	}
	log.Printf("Clé publique du client : %x", pubKey)

	// Réaliser le handshake côté client et établir une session sécurisée.
	session, err := communication.NewClientSessionWithHandshake(conn, privKey)
	if err != nil {
		log.Fatalf("Erreur lors du handshake : %v", err)
	}
	log.Println("Handshake réussi, session sécurisée établie")

	// Boucle d'envoi et de réception de messages.
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Entrez un message (ou 'quit' pour quitter) : ")
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Erreur de lecture : %v", err)
			continue
		}
		text = strings.TrimSpace(text)
		if text == "quit" {
			break
		}

		// Envoyer le message via la session sécurisée.
		if err := session.SendSecureMessage(text, 1, 60); err != nil {
			log.Printf("Erreur lors de l'envoi du message : %v", err)
			continue
		}

		// Recevoir la réponse du serveur.
		reply, err := session.ReceiveSecureMessage()
		if err != nil {
			log.Printf("Erreur lors de la réception de la réponse : %v", err)
			continue
		}
		fmt.Printf("Réponse du serveur : %s\n", reply)
	}
}
