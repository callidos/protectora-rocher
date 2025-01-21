package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"protocole-comm/pkg/communication"
	"strings"
	"sync"
)

type Message struct {
	Sender           string `json:"sender"`
	Recipient        string `json:"recipient"`
	EncryptedMessage string `json:"encrypted_message"`
}

var (
	mutex          sync.Mutex
	messageFile    = "messages.json"
	messageHistory []Message
)

func main() {
	loadMessagesFromFile()

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

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(conn)

	if !scanner.Scan() {
		return
	}
	username := strings.TrimSpace(scanner.Text())

	sendMessageHistory(username, conn)

	for scanner.Scan() {
		fullMessage := strings.TrimSpace(scanner.Text())
		parts := strings.Split(fullMessage, "|")
		if len(parts) != 2 {
			continue
		}

		header := strings.TrimSpace(parts[0])
		receivedHMAC := strings.TrimSpace(parts[1])

		expectedHMAC := communication.GenerateHMAC(header, sharedKey[:])
		if receivedHMAC != expectedHMAC {
			continue
		}

		headerParts := strings.SplitN(header, ": ", 2)
		if len(headerParts) != 2 {
			continue
		}

		encryptedMessage := headerParts[1]
		decryptedMessage, err := communication.DecryptAES(encryptedMessage, sharedKey[:])
		if err != nil {
			continue
		}

		messageParts := strings.SplitN(string(decryptedMessage), "|", 3)
		if len(messageParts) != 3 {
			continue
		}

		sender := messageParts[0]
		recipient := messageParts[1]
		storeMessage(sender, recipient, encryptedMessage)
		fmt.Printf("[%s -> %s]\n", sender, recipient)
	}
}

func sendMessageHistory(username string, conn net.Conn) {
	mutex.Lock()
	defer mutex.Unlock()

	var hasMessages bool
	for _, msg := range messageHistory {
		if msg.Recipient == username {
			fmt.Fprintf(conn, "%s: %s\n", msg.Sender, msg.EncryptedMessage)
			hasMessages = true
		}
	}

	if !hasMessages {
		fmt.Fprintln(conn, "Aucun message enregistré.")
	}

	fmt.Fprintln(conn, "==========================")
}

func storeMessage(sender, recipient, encryptedMessage string) {
	mutex.Lock()
	defer mutex.Unlock()

	newMessage := Message{
		Sender:           sender,
		Recipient:        recipient,
		EncryptedMessage: encryptedMessage,
	}

	messageHistory = append(messageHistory, newMessage)

	err := saveMessagesToFile()
	if err != nil {
		fmt.Println("Erreur lors de la sauvegarde des messages :", err)
	}
}

func saveMessagesToFile() error {
	file, err := os.Create(messageFile)
	if err != nil {
		return fmt.Errorf("erreur lors de l'ouverture du fichier : %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(messageHistory)
}

func loadMessagesFromFile() {
	file, err := os.Open(messageFile)
	if err != nil {
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.Decode(&messageHistory)
}
