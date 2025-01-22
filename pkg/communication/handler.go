package communication

import (
	"bufio"
	"fmt"
	"net"
	"protectora-rocher/pkg/utils"
	"strings"
	"sync"
	"time"
)

func HandleConnection(conn net.Conn, sharedKey []byte, wg *sync.WaitGroup) {
	defer conn.Close()

	// Définir une limite de lecture de 5 minutes
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	utils.LogInfo("Nouvelle connexion acceptée", map[string]interface{}{
		"remote_addr": conn.RemoteAddr().String(),
	})

	scanner := bufio.NewScanner(conn)

	// Lire le nom d'utilisateur
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

	// Envoi du message de bienvenue
	if err := sendWelcomeMessage(conn, sharedKey, username); err != nil {
		utils.LogError("Erreur d'envoi du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	messageChan := make(chan string)
	doneChan := make(chan bool)

	// Goroutine pour lire les messages envoyés par le client
	go func() {
		for scanner.Scan() {
			receivedMessage := strings.TrimSpace(scanner.Text())
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

	// Gestion des messages reçus
	for {
		select {
		case receivedMessage := <-messageChan:
			// Ajouter un délai pour s'assurer que chaque message est traité
			time.Sleep(1 * time.Second) // Attente pour garantir que chaque message soit traité
			if err := processIncomingMessage(receivedMessage, sharedKey, conn, username); err != nil {
				utils.LogError("Erreur lors du traitement du message", map[string]interface{}{
					"error":   err.Error(),
					"message": receivedMessage,
				})
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		case <-doneChan:
			// Ajouter l'attente de l'accusé de réception via WaitGroup
			wg.Add(1)
			if err := sendAcknowledgment(conn, sharedKey, wg); err != nil {
				utils.LogError("Erreur lors de l'envoi de l'accusé de réception", map[string]interface{}{"error": err.Error()})
			}

			utils.LogInfo("Fin de communication avec le client", map[string]interface{}{
				"username": username,
				"remote":   conn.RemoteAddr().String(),
			})
			return
		}
	}

	// Vérification d'une erreur lors de la lecture du scanner
	if err := scanner.Err(); err != nil {
		utils.LogError("Erreur de lecture de la connexion", map[string]interface{}{
			"error": err.Error(),
			"user":  username,
		})
	}
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, conn net.Conn, username string) error {
	// Séparer le message et le HMAC
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	// Vérification de l'intégrité du message avec HMAC
	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	// Déchiffrement du message
	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	utils.LogInfo("Message reçu et déchiffré", map[string]interface{}{
		"user":    username,
		"message": string(decryptedMessage),
	})

	// Envoi de l'accusé de réception
	if err := sendAcknowledgment(conn, sharedKey, nil); err != nil {
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

	// Chiffrement du message de bienvenue
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

func sendAcknowledgment(conn net.Conn, sharedKey []byte, wg *sync.WaitGroup) error {
	if wg != nil {
		defer wg.Done() // Indique que cette goroutine est terminée lorsque la fonction retourne.
	}

	ackMessage := "Message reçu avec succès."
	utils.LogInfo("Envoi de l'accusé de réception", map[string]interface{}{
		"ackMessage": ackMessage,
		"remote":     conn.RemoteAddr().String(),
	})

	// Attendre un instant pour s'assurer que tout est prêt avant d'envoyer l'accusé
	time.Sleep(500 * time.Millisecond)

	// Assurer le bon format de l'accusé de réception (avec HMAC)
	encryptedAck, err := EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := GenerateHMAC(encryptedAck, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	// Log final pour confirmer l'envoi de l'accusé de réception
	utils.LogInfo("Accusé de réception envoyé avec succès", map[string]interface{}{
		"ackMessage": ackMessage,
		"remote":     conn.RemoteAddr().String(),
	})

	return nil
}
