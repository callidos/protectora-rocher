package communication

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func HandleConnection(conn net.Conn, sharedKey []byte) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		receivedMessage := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(receivedMessage, "|", 2)
		if len(parts) != 2 {
			fmt.Println("Message malformé")
			continue
		}

		encryptedMessage := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
		if receivedHMAC != expectedHMAC {
			fmt.Println("Erreur : HMAC invalide, message rejeté")
			continue
		}

		decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			fmt.Println("Erreur de déchiffrement:", err)
			continue
		}

		uncompressedMessage, err := DecompressData(decryptedMessage)
		if err != nil {
			fmt.Println("Erreur de décompression:", err)
			continue
		}

		messageParts := strings.SplitN(string(uncompressedMessage), "|", 2)
		if len(messageParts) != 2 {
			fmt.Println("Format du message incorrect")
			continue
		}

		sequenceNumber := messageParts[0]
		messageContent := messageParts[1]

		fmt.Printf("Message reçu [%s]: %s\n", sequenceNumber, messageContent)
	}
}
