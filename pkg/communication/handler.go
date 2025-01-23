package communication

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"protectora-rocher/pkg/utils"
	"strings"
)

func HandleConnection(reader io.Reader, writer io.Writer, sharedKey []byte) {
	utils.Logger.Info("Nouvelle connexion traitée", map[string]interface{}{})

	scanner := bufio.NewScanner(reader)

	if !scanner.Scan() {
		utils.Logger.Warning("Erreur de lecture du nom d'utilisateur", map[string]interface{}{})
		return
	}
	username := strings.TrimSpace(scanner.Text())

	utils.Logger.Info("Utilisateur connecté", map[string]interface{}{
		"username": username,
	})

	if err := sendWelcomeMessage(writer, sharedKey, username); err != nil {
		utils.Logger.Error("Erreur d'envoi du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	messageChan := make(chan string)
	doneChan := make(chan bool)

	go func() {
		for scanner.Scan() {
			receivedMessage := strings.TrimSpace(scanner.Text())
			utils.Logger.Debug("Message reçu", map[string]interface{}{
				"message": receivedMessage,
			})
			if receivedMessage == "FIN_SESSION" {
				utils.Logger.Info("Fin de session demandée par l'utilisateur", map[string]interface{}{
					"username": username,
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
			if err := processIncomingMessage(receivedMessage, sharedKey, writer, username); err != nil {
				utils.Logger.Error("Erreur lors du traitement du message", map[string]interface{}{
					"error":   err.Error(),
					"message": receivedMessage,
				})
			}
			if err := sendAcknowledgment(writer, sharedKey); err != nil {
				utils.Logger.Error("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{
					"error": err.Error(),
				})
			}

		case <-doneChan:
			utils.Logger.Info("Fin de communication avec l'utilisateur", map[string]interface{}{
				"username": username,
			})
			return
		}
	}
}

// processIncomingMessage traite un message reçu et vérifie son intégrité.
func processIncomingMessage(receivedMessage string, sharedKey []byte, writer io.Writer, username string) error {
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

	if !bytes.Equal([]byte(receivedHMAC), []byte(expectedHMAC)) {
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

	if err := sendAcknowledgment(writer, sharedKey); err != nil {
		utils.LogError("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("erreur d'envoi de l'accusé de réception : %v", err)
	}

	utils.LogInfo("Accusé de réception envoyé avec succès", map[string]interface{}{
		"user": username,
	})

	return nil
}

// sendWelcomeMessage envoie un message de bienvenue chiffré au client.
func sendWelcomeMessage(writer io.Writer, sharedKey []byte, username string) error {
	welcomeMessage := fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", username)

	encryptedMessage, err := EncryptAESGCM([]byte(welcomeMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement du message de bienvenue: %v", err)
	}

	hmac := GenerateHMAC(encryptedMessage, sharedKey)
	_, err = fmt.Fprintf(writer, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message de bienvenue: %v", err)
	}

	utils.LogInfo("Message de bienvenue envoyé avec succès", map[string]interface{}{
		"username": username,
	})

	return nil
}

// sendAcknowledgment envoie un accusé de réception au client.
func sendAcknowledgment(writer io.Writer, sharedKey []byte) error {
	ackMessage := "Message reçu avec succès."

	encryptedAck, err := EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := GenerateHMAC(encryptedAck, sharedKey)
	_, err = fmt.Fprintf(writer, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	utils.LogInfo("Accusé de réception envoyé avec succès", map[string]interface{}{})

	return nil
}
