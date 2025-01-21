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

	log.Println("Nouvelle connexion acceptée...")

	sharedKey, err := communication.PerformKeyExchange(conn)
	if err != nil {
		log.Println("Erreur d'échange de clés :", err)
		return
	}
	log.Printf("Échange de clés réussi. Clé partagée : %x\n", sharedKey)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		fullMessage := strings.TrimSpace(scanner.Text())

		log.Println("Message brut reçu :", fullMessage)

		parts := strings.Split(fullMessage, "|")
		if len(parts) != 2 {
			log.Println("Message malformé (pas de séparateur '|' trouvé). Reçu :", fullMessage)
			continue
		}

		header := strings.TrimSpace(parts[0])
		receivedHMAC := strings.TrimSpace(parts[1])

		log.Println("Header reçu (avant HMAC) :", header)
		log.Println("HMAC reçu :", receivedHMAC)

		expectedHMAC := communication.GenerateHMAC(header, sharedKey[:])
		log.Println("HMAC attendu :", expectedHMAC)

		if receivedHMAC != expectedHMAC {
			log.Println("ERREUR: HMAC invalide. Le message a peut-être été altéré.")
			continue
		}
		log.Println("HMAC vérifié avec succès.")

		headerParts := strings.SplitN(header, ": ", 2)
		if len(headerParts) != 2 {
			log.Println("Format du message incorrect. Reçu :", header)
			continue
		}

		username := headerParts[0]
		encryptedMessage := headerParts[1]

		decryptedMessage, err := communication.DecryptAES(encryptedMessage, sharedKey[:])
		if err != nil {
			log.Println("Erreur de déchiffrement du message :", err)
			continue
		}

		log.Printf("[%s] %s\n", username, string(decryptedMessage))
		fmt.Printf("[%s] %s\n", username, string(decryptedMessage))
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Erreur de lecture du message : %v\n", err)
	}
}
