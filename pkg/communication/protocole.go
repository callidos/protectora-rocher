package communication

import (
	"fmt"
	"net"
)

func SendMessage(conn net.Conn, message string, sharedKey []byte) error {
	encryptedMessage, err := encryptAES([]byte(message), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmac := generateHMAC(encryptedMessage, sharedKey)

	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de message: %v", err)
	}

	return nil
}
