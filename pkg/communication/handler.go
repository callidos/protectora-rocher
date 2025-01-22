package communication

import (
	"bufio"
	"fmt"
	"net"
	"protectora-rocher/pkg/utils"
	"strings"
	"time"
)

func HandleConnection(conn net.Conn, sharedKey []byte) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	utils.LogInfo("Nouvelle connexion acceptée", map[string]interface{}{
		"remote_addr": conn.RemoteAddr().String(),
	})

	scanner := bufio.NewScanner(conn)

	if !scanner.Scan() {
		utils.LogWarning("Erreur de lecture du nom d'utilisateur", map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
		})
		return
	}
	username := strings.TrimSpace(scanner.Text())

	utils.LogInfo("Utilisateur connecté", map[string]interface{}{
		"username": username,
		"remote":   conn.RemoteAddr().String(),
	})

	err := sendWelcomeMessage(conn, sharedKey, username)
	if err != nil {
		utils.LogError("Erreur d'envoi du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	for scanner.Scan() {
		receivedMessage := strings.TrimSpace(scanner.Text())

		if receivedMessage == "FIN_SESSION" {
			utils.LogInfo("Fin de session demandée par l'utilisateur", map[string]interface{}{
				"username": username,
				"remote":   conn.RemoteAddr().String(),
			})
			break
		}

		err := processIncomingMessage(receivedMessage, sharedKey, conn, username)
		if err != nil {
			utils.LogError("Erreur de traitement du message", map[string]interface{}{
				"error": err.Error(),
				"user":  username,
			})
			break
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	}

	if err := scanner.Err(); err != nil {
		utils.LogError("Erreur de lecture de la connexion", map[string]interface{}{
			"error": err.Error(),
			"user":  username,
		})
	}

	utils.LogInfo("Fin de communication avec le client", map[string]interface{}{
		"username": username,
		"remote":   conn.RemoteAddr().String(),
	})
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, conn net.Conn, username string) error {
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	fmt.Printf("Message reçu de %s : %s\n", username, string(decryptedMessage))

	err = sendAcknowledgment(conn, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception : %v", err)
	}

	return nil
}

func sendWelcomeMessage(conn net.Conn, sharedKey []byte, username string) error {
	welcomeMessage := fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", username)

	encryptedMessage, err := EncryptAESGCM([]byte(welcomeMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement du message de bienvenue: %v", err)
	}

	hmac := GenerateHMAC(encryptedMessage, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message de bienvenue: %v", err)
	}

	utils.LogInfo("Message de bienvenue envoyé avec succès", map[string]interface{}{
		"username": username,
	})

	return nil
}

func sendAcknowledgment(conn net.Conn, sharedKey []byte) error {
	ackMessage := "Message reçu avec succès."

	encryptedAck, err := EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := GenerateHMAC(encryptedAck, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	return nil
}
