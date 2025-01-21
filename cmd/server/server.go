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

	fmt.Println("Serveur démarré sur le port 8080...")

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

		username := headerParts[0]
		encryptedMessage := headerParts[1]

		decryptedMessage, err := communication.DecryptAES(encryptedMessage, sharedKey[:])
		if err != nil {
			continue
		}

		fmt.Printf("[%s] %s\n", username, string(decryptedMessage))
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Erreur de lecture du message : %v\n", err)
	}
}
