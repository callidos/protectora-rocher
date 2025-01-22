package communication

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

func DialTor(address string) (net.Conn, error) {
	torProxy := "127.0.0.1:9050"
	dialer, err := proxy.SOCKS5("tcp", torProxy, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("échec de la connexion via Tor: %v", err)
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("échec de l'établissement de la connexion via Tor: %v", err)
	}

	return conn, nil
}

func SendSecureMessageViaTor(address string, message string, sharedKey []byte) error {
	conn, err := DialTor(address)
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	encryptedMessage, err := EncryptAESGCM([]byte(message), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmac := GenerateHMAC(encryptedMessage, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("échec de l'envoi via Tor: %v", err)
	}

	return nil
}
