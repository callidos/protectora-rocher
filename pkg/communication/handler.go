package communication

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"io"
	"protectora-rocher/pkg/utils"
	"strings"
	"time"
)

func HandleConnection(reader io.Reader, writer io.Writer, sharedKey []byte) {
	utils.Logger.Info("Nouvelle connexion traitée", map[string]interface{}{})

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // Augmenter la taille du buffer

	// Lire le nom d'utilisateur
	if !scanner.Scan() {
		utils.Logger.Warning("Erreur de lecture du nom d'utilisateur", map[string]interface{}{})
		fmt.Fprintln(writer, "Erreur: Impossible de lire le nom d'utilisateur")
		return
	}

	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		// Cas où le nom d'utilisateur est vide, on ferme la connexion et on envoie un message d'erreur
		utils.Logger.Warning("Nom d'utilisateur vide, fermeture de la connexion", map[string]interface{}{})
		fmt.Fprintln(writer, "Erreur: Impossible de lire le nom d'utilisateur ou nom d'utilisateur vide")

		// Ajouter un log avant de fermer la connexion
		utils.Logger.Debug("Fermeture de la connexion due à un nom d'utilisateur vide", map[string]interface{}{})

		// Fermer la connexion si le nom d'utilisateur est vide
		if closer, ok := writer.(io.Closer); ok {
			closer.Close()
		}
		return
	}

	utils.Logger.Info("Utilisateur connecté", map[string]interface{}{
		"username": username,
	})

	// Envoi du message de bienvenue
	if err := sendWelcomeMessage(writer, sharedKey, username); err != nil {
		utils.Logger.Error("Erreur d'envoi du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	messageChan := make(chan string)
	doneChan := make(chan bool)

	// Goroutine pour traiter les messages entrants
	go func() {
		for scanner.Scan() {
			receivedMessage := strings.TrimSpace(scanner.Text())
			utils.Logger.Debug("Message reçu", map[string]interface{}{
				"message": receivedMessage,
			})

			// Si le message est "FIN_SESSION", fermer la session
			if receivedMessage == "FIN_SESSION" {
				utils.Logger.Info("Fin de session demandée par l'utilisateur", map[string]interface{}{
					"username": username,
				})
				doneChan <- true
				return
			}

			// Sinon, envoyer le message au canal de traitement
			messageChan <- receivedMessage
		}

		if err := scanner.Err(); err != nil {
			utils.Logger.Error("Erreur de lecture de la connexion", map[string]interface{}{
				"error": err.Error(),
			})
		}
		doneChan <- true
	}()

	// Fermeture de la connexion si nécessaire
	defer func() {
		if closer, ok := writer.(io.Closer); ok {
			closer.Close()
		}
	}()

	// Traitement des messages reçus
	for {
		select {
		case receivedMessage := <-messageChan:
			// Traitement du message entrant
			if err := processIncomingMessage(receivedMessage, sharedKey, writer, username); err != nil {
				utils.Logger.Error("Erreur lors du traitement du message", map[string]interface{}{
					"error":   err.Error(),
					"message": receivedMessage,
				})
			}

			// Envoi de l'accusé de réception
			if err := sendAcknowledgment(writer, sharedKey); err != nil {
				utils.Logger.Error("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{
					"error": err.Error(),
				})
			}

		case <-doneChan:
			// Fin de la session
			utils.Logger.Info("Fin de communication avec l'utilisateur", map[string]interface{}{
				"username": username,
			})
			return
		}
	}
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, writer io.Writer, username string) error {
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := strings.TrimSpace(parts[1])

	utils.Logger.Info("Message reçu", map[string]interface{}{
		"encrypted_message": encryptedMessage,
		"received_hmac":     receivedHMAC,
	})

	if _, err := base64.StdEncoding.DecodeString(encryptedMessage); err != nil {
		return fmt.Errorf("message mal encodé : %v", err)
	}

	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
	if !hmac.Equal([]byte(receivedHMAC), []byte(expectedHMAC)) {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	utils.Logger.Info("Message reçu et déchiffré", map[string]interface{}{
		"user":    username,
		"message": string(decryptedMessage),
	})

	if err := sendAcknowledgment(writer, sharedKey); err != nil {
		utils.Logger.Error("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("erreur d'envoi de l'accusé de réception : %v", err)
	}

	utils.Logger.Info("Accusé de réception envoyé avec succès", map[string]interface{}{
		"user": username,
	})

	return nil
}

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

	utils.Logger.Info("Message de bienvenue envoyé avec succès", map[string]interface{}{
		"username": username,
	})

	return nil
}

func sendAcknowledgment(writer io.Writer, sharedKey []byte) error {
	ackMessage := "Message reçu avec succès."

	encryptedAck, err := EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := GenerateHMAC(encryptedAck, sharedKey)

	if w, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		w.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}

	_, err = fmt.Fprintf(writer, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	utils.Logger.Info("Accusé de réception envoyé avec succès", map[string]interface{}{})

	return nil
}
