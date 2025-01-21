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

	publicKey, privateKey, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatalf("Erreur lors de la génération des clés : %v", err)
	}

	sharedKey, err := communication.PerformAuthenticatedKeyExchange(conn, privateKey, publicKey)
	if err != nil {
		log.Fatalf("Erreur d'échange de clés : %v\n", err)
	}
	fmt.Println("Échange de clés réussi, communication sécurisée établie.")

	fmt.Print("Entrez votre nom d'utilisateur : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	_, err = fmt.Fprintf(conn, "%s\n", username)
	if err != nil {
		log.Fatalf("Erreur lors de l'envoi du nom d'utilisateur : %v\n", err)
	}

	err = receiveWelcomeMessage(conn, sharedKey[:])
	if err != nil {
		log.Fatalf("Erreur de réception du message de bienvenue : %v\n", err)
	}

	fmt.Println("Vous pouvez maintenant envoyer des messages. Tapez 'exit' pour quitter.")

	sequenceNumber := uint64(0)
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

		sequenceNumber++
		fullMessage := fmt.Sprintf("%s|%s", recipient, message)
		err := sendMessage(conn, sharedKey[:], fullMessage, sequenceNumber)
		if err != nil {
			log.Println("Erreur lors de l'envoi du message :", err)
			continue
		}

		fmt.Println("Message envoyé.")
	}

	fmt.Println("Déconnexion du serveur.")
}

func sendMessage(conn net.Conn, sharedKey []byte, message string, sequenceNumber uint64) error {
	formattedMessage := fmt.Sprintf("%d|%s", sequenceNumber, message)

	encryptedMessage, err := communication.EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)

	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message: %v", err)
	}

	err = receiveAcknowledgment(conn, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de réception de l'accusé de réception: %v", err)
	}

	return nil
}

func receiveWelcomeMessage(conn net.Conn, sharedKey []byte) error {
	scanner := bufio.NewScanner(conn)

	if scanner.Scan() {
		receivedMessage := scanner.Text()
		parts := strings.SplitN(receivedMessage, "|", 2)
		if len(parts) != 2 {
			return fmt.Errorf("message de bienvenue mal formé")
		}

		encryptedMessage := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
		if receivedHMAC != expectedHMAC {
			return fmt.Errorf("HMAC invalide pour le message de bienvenue")
		}

		decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			return fmt.Errorf("erreur de déchiffrement du message de bienvenue : %v", err)
		}

		fmt.Println("Serveur :", string(decryptedMessage))
	}

	return nil
}

func receiveAcknowledgment(conn net.Conn, sharedKey []byte) error {
	scanner := bufio.NewScanner(conn)

	if scanner.Scan() {
		receivedMessage := scanner.Text()
		parts := strings.SplitN(receivedMessage, "|", 2)
		if len(parts) != 2 {
			return fmt.Errorf("accusé de réception mal formé")
		}

		encryptedMessage := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
		if receivedHMAC != expectedHMAC {
			return fmt.Errorf("HMAC invalide pour l'accusé de réception")
		}

		decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			return fmt.Errorf("erreur de déchiffrement de l'accusé de réception : %v", err)
		}

		fmt.Println("Serveur :", string(decryptedMessage))
	}

	return nil
}
