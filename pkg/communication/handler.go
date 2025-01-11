package communication

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func HandleConnection(conn net.Conn) {
	defer conn.Close()

	sharedKey, err := PerformKeyExchange(conn)
	if err != nil {
		fmt.Println("Erreur d'échange de clés:", err)
		return
	}

	sharedKeySlice := sharedKey[:]

	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("Erreur de lecture:", err)
		return
	}

	parts := strings.Split(message, "|")
	if len(parts) != 2 {
		fmt.Println("Message malformé")
		return
	}
	encryptedMessage := parts[0]
	receivedHMAC := parts[1][:len(parts[1])-1]

	expectedHMAC := generateHMAC(encryptedMessage, sharedKeySlice)
	if receivedHMAC != expectedHMAC {
		fmt.Println("Erreur : HMAC invalide")
		return
	}

	decryptedMessage, err := decryptAES(encryptedMessage, sharedKeySlice)
	if err != nil {
		fmt.Println("Erreur de déchiffrement:", err)
		return
	}

	fmt.Println("Message reçu :", string(decryptedMessage))
}
