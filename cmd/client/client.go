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

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		log.Fatalf("Erreur d'échange de clés : %v\n", err)
	}

	fmt.Print("Entrez votre nom d'utilisateur : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	for {
		fmt.Print("Entrez votre message (ou 'exit' pour quitter) : ")
		scanner.Scan()
		message := strings.TrimSpace(scanner.Text())

		if message == "exit" {
			break
		}

		encryptedMessage, err := communication.EncryptAES([]byte(message), sharedKey[:])
		if err != nil {
			log.Fatalf("Erreur de chiffrement : %v\n", err)
		}

		header := fmt.Sprintf("%s: %s", username, encryptedMessage)
		hmacValue := communication.GenerateHMAC(header, sharedKey[:])

		fullMessage := fmt.Sprintf("%s|%s", header, hmacValue)

		_, err = fmt.Fprintf(conn, "%s\n", fullMessage)
		if err != nil {
			log.Fatalf("Erreur d'envoi du message : %v\n", err)
		}

		fmt.Println("Message envoyé avec succès.")
	}
}
