package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"protocole-comm/pkg/communication"
	"strings"
)

func main() {
	serverAddress := "localhost:8080"

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatalf("Erreur de connexion au serveur : %v\n", err)
	}
	defer conn.Close()

	log.Println("Connexion établie avec le serveur...")

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		log.Fatalf("Erreur d'échange de clés : %v\n", err)
	}

	log.Printf("Échange de clés réussi. Clé partagée : %x\n", sharedKey)

	fmt.Print("Entrez votre nom d'utilisateur : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	for {
		fmt.Print("Entrez votre message (ou 'exit' pour quitter) : ")
		scanner.Scan()
		message := strings.TrimSpace(scanner.Text())

		if message == "exit" {
			log.Println("Déconnexion du serveur...")
			break
		}

		encryptedMessage, err := communication.EncryptAES([]byte(message), sharedKey[:])
		if err != nil {
			log.Fatalf("Erreur de chiffrement : %v\n", err)
		}
		log.Println("Message chiffré (base64) :", encryptedMessage)

		header := fmt.Sprintf("%s: %s", username, encryptedMessage)
		log.Println("Header construit (nom d'utilisateur + message chiffré) :", header)

		hmacValue := communication.GenerateHMAC(header, sharedKey[:])
		log.Println("HMAC généré :", hmacValue)

		fullMessage := fmt.Sprintf("%s|%s", header, hmacValue)
		log.Println("Message complet envoyé :", fullMessage)

		_, err = fmt.Fprintf(conn, "%s\n", fullMessage)
		if err != nil {
			log.Fatalf("Erreur d'envoi du message : %v\n", err)
		}

		fmt.Println("Message envoyé avec succès.")
	}
}
