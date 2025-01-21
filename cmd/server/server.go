package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"protocole-comm/pkg/communication"
	"protocole-comm/pkg/utils"
	"strings"
	"sync"
	"time"
)

const (
	maxClients        = 100
	connectionTimeout = 5 * time.Minute
)

var (
	clientCount int
	mutex       sync.Mutex
)

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Erreur d'écoute : %v\n", err)
	}
	defer listener.Close()

	utils.LogInfo("Serveur démarré", map[string]interface{}{
		"port": 8080,
	})

	for {
		conn, err := listener.Accept()
		if err != nil {
			utils.LogWarning("Erreur d'acceptation de connexion", map[string]interface{}{
				"error": err.Error(),
			})
			continue
		}

		mutex.Lock()
		if clientCount >= maxClients {
			mutex.Unlock()
			utils.LogWarning("Connexion refusée - limite atteinte", map[string]interface{}{
				"remote_addr": conn.RemoteAddr().String(),
			})
			conn.Close()
			continue
		}
		clientCount++
		mutex.Unlock()

		utils.LogInfo("Nouvelle connexion acceptée", map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
		})

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	defer func() {
		mutex.Lock()
		clientCount--
		mutex.Unlock()
		utils.LogInfo("Client déconnecté", map[string]interface{}{
			"remote_addr": conn.RemoteAddr().String(),
		})
	}()

	conn.SetDeadline(time.Now().Add(connectionTimeout))

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
	utils.LogInfo("Échange de clés réussi, communication sécurisée établie", map[string]interface{}{
		"remote_addr": conn.RemoteAddr().String(),
	})

	err = handleClientCommunication(conn, sharedKey[:])
	if err != nil {
		utils.LogError("Erreur dans la gestion de la communication", map[string]interface{}{
			"error":       err.Error(),
			"remote_addr": conn.RemoteAddr().String(),
		})
	}
}

func handleClientCommunication(conn net.Conn, sharedKey []byte) error {
	scanner := bufio.NewScanner(conn)

	if !scanner.Scan() {
		return fmt.Errorf("échec de la lecture du nom d'utilisateur")
	}
	username := scanner.Text()
	utils.LogInfo("Utilisateur connecté", map[string]interface{}{
		"username": username,
		"remote":   conn.RemoteAddr().String(),
	})

	err := sendWelcomeMessage(conn, sharedKey, username)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message de bienvenue : %v", err)
	}

	for scanner.Scan() {
		message := scanner.Text()
		err := processIncomingMessage(message, sharedKey, conn, username)
		if err != nil {
			utils.LogWarning("Erreur lors du traitement du message", map[string]interface{}{
				"error": err.Error(),
				"from":  username,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("erreur de lecture des messages : %v", err)
	}

	return nil
}

func processIncomingMessage(receivedMessage string, sharedKey []byte, conn net.Conn, username string) error {
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	expectedHMAC := communication.GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := communication.DecryptAESGCM(encryptedMessage, sharedKey)
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

	encryptedMessage, err := communication.EncryptAESGCM([]byte(welcomeMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement du message de bienvenue: %v", err)
	}

	hmac := communication.GenerateHMAC(encryptedMessage, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message de bienvenue: %v", err)
	}

	return nil
}

func sendAcknowledgment(conn net.Conn, sharedKey []byte) error {
	ackMessage := "Message reçu avec succès."

	encryptedAck, err := communication.EncryptAESGCM([]byte(ackMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement de l'accusé de réception: %v", err)
	}

	hmac := communication.GenerateHMAC(encryptedAck, sharedKey)
	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedAck, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi de l'accusé de réception: %v", err)
	}

	return nil
}
