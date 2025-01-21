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

	fmt.Println("Connexion au serveur...")

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatalf("Impossible de se connecter au serveur : %v\n", err)
	}
	defer conn.Close()
	fmt.Println("Connecté au serveur.")

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		log.Fatalf("Erreur d'échange de clés : %v\n", err)
	}

	fmt.Print("Entrez votre nom d'utilisateur : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	fmt.Fprintf(conn, "%s\n", username)

	printMessageHistory(conn, sharedKey)

	fmt.Println("Vous pouvez maintenant envoyer des messages. Tapez 'exit' pour quitter.")
	startMessaging(conn, sharedKey, username)
	fmt.Println("Déconnexion du serveur.")
}

func printMessageHistory(conn net.Conn, sharedKey [32]byte) {
	reader := bufio.NewReader(conn)

	for {
		historyLine, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Erreur de lecture de l'historique : %v\n", err)
		}
		historyLine = strings.TrimSpace(historyLine)
		if historyLine == "==========================" {
			break
		}

		parts := strings.SplitN(historyLine, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		sender := parts[0]
		encryptedMessage := parts[1]

		decryptedMessage, err := communication.DecryptAES(encryptedMessage, sharedKey[:])
		if err != nil {
			continue
		}

		fmt.Printf("Message de %s : %s\n", sender, string(decryptedMessage))
	}
}

func startMessaging(conn net.Conn, sharedKey [32]byte, username string) {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("Destinataire : ")
		scanner.Scan()
		recipient := strings.TrimSpace(scanner.Text())

		if recipient == "exit" {
			break
		}

		fmt.Print("Message : ")
		scanner.Scan()
		message := strings.TrimSpace(scanner.Text())

		if message == "exit" {
			break
		}

		messageFormat := fmt.Sprintf("%s|%s|%s", username, recipient, message)

		encryptedMessage, err := communication.EncryptAES([]byte(messageFormat), sharedKey[:])
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

		fmt.Printf("Message envoyé à %s.\n", recipient)
	}
}
