package communication

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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

	if err := sendWelcomeMessage(conn, sharedKey, username); err != nil {
		utils.LogError("Erreur d'envoi du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	messageChan := make(chan string)
	doneChan := make(chan bool)

	go func() {
		for scanner.Scan() {
			receivedMessage := strings.TrimSpace(scanner.Text())
			utils.LogDebug("Message reçu du client", map[string]interface{}{
				"message": receivedMessage,
				"remote":  conn.RemoteAddr().String(),
			})
			if receivedMessage == "FIN_SESSION" {
				utils.LogInfo("Fin de session demandée par l'utilisateur", map[string]interface{}{
					"username": username,
					"remote":   conn.RemoteAddr().String(),
				})
				doneChan <- true
				return
			}
			messageChan <- receivedMessage
		}
		doneChan <- true
	}()

	for {
		select {
		case receivedMessage := <-messageChan:
			if err := processIncomingMessage(receivedMessage, sharedKey, conn, username); err != nil {
				utils.LogError("Erreur lors du traitement du message", map[string]interface{}{
					"error":   err.Error(),
					"message": receivedMessage,
				})
			}
			if err := sendAcknowledgment(conn, sharedKey); err != nil {
				utils.LogError("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{"error": err.Error()})
			}

			output := getBufferContents(conn)
			utils.LogDebug("État du buffer après envoi de l'accusé", map[string]interface{}{
				"output": output,
			})

			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case <-doneChan:
			if err := sendAcknowledgment(conn, sharedKey); err != nil {
				utils.LogError("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{"error": err.Error()})
			}

			utils.LogInfo("Fin de communication avec le client", map[string]interface{}{
				"username": username,
				"remote":   conn.RemoteAddr().String(),
			})
			return
		}
	}
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, conn net.Conn, username string) error {
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := strings.TrimSpace(parts[1])

	utils.LogInfo("Message reçu", map[string]interface{}{
		"encrypted_message": encryptedMessage,
		"received_hmac":     receivedHMAC,
	})

	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)

	receivedHMAC = strings.ReplaceAll(receivedHMAC, " ", "")
	expectedHMAC = strings.ReplaceAll(expectedHMAC, " ", "")

	receivedHMACBytes := []byte(receivedHMAC)
	expectedHMACBytes := []byte(expectedHMAC)

	if !bytes.Equal(receivedHMACBytes, expectedHMACBytes) {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	utils.LogInfo("Message reçu et déchiffré", map[string]interface{}{
		"user":    username,
		"message": string(decryptedMessage),
	})

	if err := sendAcknowledgment(conn, sharedKey); err != nil {
		utils.LogError("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("erreur d'envoi de l'accusé de réception : %v", err)
	}

	utils.LogInfo("Accusé de réception envoyé avec succès", map[string]interface{}{
		"user": username,
	})

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
	utils.LogInfo("Préparation de l'accusé de réception", map[string]interface{}{
		"ackMessage": ackMessage,
		"remote":     conn.RemoteAddr().String(),
	})

	encryptedAck, err := EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		utils.LogError("Erreur lors du chiffrement de l'accusé de réception", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	utils.LogDebug("Accusé de réception chiffré", map[string]interface{}{
		"encrypted_ack": encryptedAck,
	})

	hmac := GenerateHMAC(encryptedAck, sharedKey)
	utils.LogDebug("HMAC généré pour l'accusé de réception", map[string]interface{}{
		"hmac": hmac,
	})

	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		utils.LogError("Erreur d'envoi de l'accusé de réception", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	utils.LogInfo("Accusé de réception envoyé avec succès", map[string]interface{}{
		"ackMessage": ackMessage,
		"remote":     conn.RemoteAddr().String(),
	})

	return nil
}

func getBufferContents(conn net.Conn) string {
	var buffer bytes.Buffer

	_, err := io.Copy(&buffer, conn)
	if err != nil {
		utils.LogError("Erreur lors de la lecture du buffer de la connexion", map[string]interface{}{"error": err.Error()})
		return ""
	}

	return buffer.String()
}
