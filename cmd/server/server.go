package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"protocole-comm/pkg/communication"
	"strings"
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Erreur d'écoute : %v\n", err)
	}
	defer listener.Close()

	fmt.Println("Serveur démarré sur le port 8080.")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Erreur d'acceptation de connexion :", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	publicKey, privateKey, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		fmt.Println("Erreur de génération des clés :", err)
		return
	}

	sharedKey, err := communication.PerformAuthenticatedKeyExchange(conn, privateKey, publicKey)
	if err != nil {
		fmt.Println("Erreur d'échange de clés :", err)
		return
	}
	fmt.Println("Échange de clés réussi, communication sécurisée établie.")

	scanner := bufio.NewScanner(conn)

	if !scanner.Scan() {
		fmt.Println("Erreur de lecture du nom d'utilisateur.")
		return
	}
	username := strings.TrimSpace(scanner.Text())
	fmt.Printf("Utilisateur connecté : %s\n", username)

	err = sendWelcomeMessage(conn, sharedKey[:])
	if err != nil {
		fmt.Println("Erreur d'envoi du message de bienvenue :", err)
		return
	}

	for scanner.Scan() {
		receivedMessage := strings.TrimSpace(scanner.Text())

		if err := processIncomingMessage(receivedMessage, sharedKey[:], conn, username); err != nil {
			fmt.Println("Erreur dans le traitement du message :", err)
		}
	}

	fmt.Printf("Utilisateur %s déconnecté.\n", username)
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, conn net.Conn, username string) error {
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message malformé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	messageParts := strings.SplitN(string(decryptedMessage), "|", 2)
	if len(messageParts) != 2 {
		return fmt.Errorf("format du message incorrect")
	}

	sequenceNumber := messageParts[0]
	messageContent := messageParts[1]

	fmt.Printf("[%s] Message reçu de %s : %s\n", sequenceNumber, username, messageContent)

	return sendAcknowledgment(conn, sharedKey, sequenceNumber)
}

func sendWelcomeMessage(conn net.Conn, sharedKey []byte) error {
	welcomeMessage := "Bienvenue sur le serveur sécurisé."

	encryptedMessage, err := communication.EncryptAESGCM([]byte(welcomeMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement du message de bienvenue: %v", err)
	}

	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message de bienvenue: %v", err)
	}

	return nil
}

func sendAcknowledgment(conn net.Conn, sharedKey []byte, sequenceNumber string) error {
	ackMessage := fmt.Sprintf("Accusé de réception du message %s", sequenceNumber)

	encryptedAck, err := communication.EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := communication.GenerateHMAC(encryptedAck, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	return nil
}
