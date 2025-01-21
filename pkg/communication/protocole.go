package communication

import (
	"fmt"
	"net"
	"strings"
)

func SendMessage(conn net.Conn, message string, sharedKey []byte, sequenceNumber uint64) error {
	formattedMessage := fmt.Sprintf("%d|%s", sequenceNumber, message)

	compressedMessage, err := CompressData([]byte(formattedMessage))
	if err != nil {
		return fmt.Errorf("erreur de compression: %v", err)
	}

	encryptedMessage, err := EncryptAESGCM(compressedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmac := GenerateHMAC(encryptedMessage, sharedKey)

	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message: %v", err)
	}

	return nil
}

func ReceiveMessage(conn net.Conn, sharedKey []byte) (string, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("erreur de lecture du message: %v", err)
	}

	receivedMessage := string(buffer[:n])
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("message malformé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return "", fmt.Errorf("HMAC invalide")
	}

	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return "", fmt.Errorf("erreur de déchiffrement: %v", err)
	}

	uncompressedMessage, err := DecompressData(decryptedMessage)
	if err != nil {
		return "", fmt.Errorf("erreur de décompression: %v", err)
	}

	return string(uncompressedMessage), nil
}
