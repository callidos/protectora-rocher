package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"protocole-comm/pkg/communication"
	"protocole-comm/pkg/utils"
	"strings"
	"sync"
)

func main() {
	serverAddress := "localhost:8080"

	utils.LogInfo("Tentative de connexion au serveur", map[string]interface{}{
		"server": serverAddress,
	})

	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		utils.LogError("Impossible de se connecter au serveur", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	defer conn.Close()
	utils.LogInfo("Connecté au serveur", nil)

	publicKey, privateKey, err := communication.GenerateEd25519KeyPair()
	if err != nil {
		utils.LogError("Erreur de génération des clés", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	sharedKey, err := communication.PerformAuthenticatedKeyExchange(conn, privateKey, publicKey)
	if err != nil {
		utils.LogError("Erreur d'échange de clés", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	utils.LogInfo("Échange de clés réussi, communication sécurisée établie", nil)

	fmt.Print("Entrez votre nom d'utilisateur : ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	_, err = fmt.Fprintf(conn, "%s\n", username)
	if err != nil {
		utils.LogError("Erreur lors de l'envoi du nom d'utilisateur", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	err = receiveWelcomeMessage(conn, sharedKey[:])
	if err != nil {
		utils.LogError("Erreur de réception du message de bienvenue", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	fmt.Println("Vous pouvez maintenant envoyer des messages. Tapez 'exit' pour quitter.")

	var wg sync.WaitGroup
	wg.Add(1)
	go listenForMessages(conn, sharedKey[:], &wg)

	sendMessages(conn, sharedKey[:], username)

	wg.Wait()
	fmt.Println("Déconnexion du serveur.")
}

func sendMessages(conn net.Conn, sharedKey []byte, username string) {
	scanner := bufio.NewScanner(os.Stdin)
	sequenceNumber := uint64(0)

	for {
		fmt.Print("Destinataire : ")
		scanner.Scan()
		recipient := strings.TrimSpace(scanner.Text())

		if recipient == "exit" {
			break
		}

		fmt.Print("Message : ")
		scanner.Scan()
		message := strings.TrimSpace(scanner.Text())

		if message == "exit" {
			break
		}

		fullMessage := fmt.Sprintf("%s|%s|%s", username, recipient, message)
		sequenceNumber++

		err := communication.SendMessage(conn, fullMessage, sharedKey, sequenceNumber)
		if err != nil {
			utils.LogError("Erreur lors de l'envoi du message", map[string]interface{}{
				"error": err.Error(),
			})
			continue
		}

		utils.LogInfo("Message envoyé avec succès", map[string]interface{}{
			"recipient": recipient,
			"username":  username,
			"sequence":  sequenceNumber,
		})
		fmt.Println("Message envoyé.")
	}
}

func listenForMessages(conn net.Conn, sharedKey []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		message, err := communication.ReceiveMessage(conn, sharedKey)
		if err != nil {
			utils.LogWarning("Erreur de réception du message", map[string]interface{}{
				"error": err.Error(),
			})
			break
		}
		fmt.Println("Message reçu :", message)
	}
}

func receiveWelcomeMessage(conn net.Conn, sharedKey []byte) error {
	scanner := bufio.NewScanner(conn)

	if scanner.Scan() {
		receivedMessage := scanner.Text()
		parts := strings.SplitN(receivedMessage, "|", 2)
		if len(parts) != 2 {
			return fmt.Errorf("message de bienvenue mal formé")
		}

		encryptedMessage := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
		if receivedHMAC != expectedHMAC {
			return fmt.Errorf("HMAC invalide pour le message de bienvenue")
		}

		decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			return fmt.Errorf("erreur de déchiffrement du message de bienvenue : %v", err)
		}

		fmt.Println("Serveur :", string(decryptedMessage))
	}

	return nil
}
