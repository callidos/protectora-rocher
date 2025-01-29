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

const bufferSize = 1024 * 1024

func HandleConnection(reader io.Reader, writer io.Writer, sharedKey []byte) {
	utils.Logger.Info("Nouvelle connexion traitée", nil)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	username, err := readUsername(scanner, writer)
	if err != nil {
		utils.Logger.Warning(err.Error(), nil)
		return
	}

	utils.Logger.Info("Utilisateur connecté", map[string]interface{}{"username": username})

	if err := sendWelcomeMessage(writer, sharedKey, username); err != nil {
		utils.Logger.Error("Erreur d'envoi du message de bienvenue", map[string]interface{}{"error": err.Error()})
		return
	}

	messageChan, doneChan := make(chan string), make(chan struct{})
	go processIncomingMessages(scanner, messageChan, doneChan, username)

	defer closeConnection(writer)

	for {
		select {
		case msg := <-messageChan:
			if err := processMessage(msg, sharedKey, writer, username); err != nil {
				utils.Logger.Error("Erreur traitement message", map[string]interface{}{"error": err.Error(), "message": msg})
			}
		case <-doneChan:
			utils.Logger.Info("Fin de communication", map[string]interface{}{"username": username})
			return
		}
	}
}

func readUsername(scanner *bufio.Scanner, writer io.Writer) (string, error) {
	if !scanner.Scan() {
		fmt.Fprintln(writer, "Erreur: Impossible de lire le nom d'utilisateur")
		return "", fmt.Errorf("lecture du nom d'utilisateur échouée")
	}

	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		fmt.Fprintln(writer, "Erreur: Nom d'utilisateur vide")
		return "", fmt.Errorf("nom d'utilisateur vide")
	}

	return username, nil
}

func processIncomingMessages(scanner *bufio.Scanner, messageChan chan<- string, doneChan chan<- struct{}, username string) {
	defer close(doneChan)

	for scanner.Scan() {
		msg := strings.TrimSpace(scanner.Text())
		if msg == "FIN_SESSION" {
			utils.Logger.Info("Fin de session demandée", map[string]interface{}{"username": username})
			return
		}
		messageChan <- msg
	}

	if err := scanner.Err(); err != nil {
		utils.Logger.Error("Erreur lecture connexion", map[string]interface{}{"error": err.Error()})
	}
}

func processMessage(msg string, sharedKey []byte, writer io.Writer, username string) error {
	parts := strings.SplitN(msg, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("message mal formé")
	}

	encryptedMsg, receivedHMACBase64 := parts[0], strings.TrimSpace(parts[1])

	// Décodage du HMAC reçu
	receivedHMAC, err := base64.StdEncoding.DecodeString(receivedHMACBase64)
	if err != nil {
		return fmt.Errorf("HMAC invalide, décodage échoué: %v", err)
	}

	// Calcul du HMAC attendu
	computedHMAC := computeHMAC([]byte(encryptedMsg), sharedKey)

	if !hmac.Equal(computedHMAC, receivedHMAC) {
		return fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMsg, err := DecryptAESGCM(encryptedMsg, sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de déchiffrement : %v", err)
	}

	utils.Logger.Info("Message reçu et déchiffré", map[string]interface{}{"user": username, "message": string(decryptedMsg)})

	return sendAcknowledgment(writer, sharedKey)
}

func sendWelcomeMessage(writer io.Writer, sharedKey []byte, username string) error {
	return sendMessage(writer, fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", username), sharedKey)
}

func sendAcknowledgment(writer io.Writer, sharedKey []byte) error {
	return sendMessage(writer, "Message reçu avec succès.", sharedKey)
}

func sendMessage(writer io.Writer, message string, sharedKey []byte) error {
	encryptedMsg, err := EncryptAESGCM([]byte(message), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur chiffrement message : %v", err)
	}

	hmac := GenerateHMAC(encryptedMsg, sharedKey)

	if w, ok := writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		w.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}

	if _, err := fmt.Fprintf(writer, "%s|%s\n", encryptedMsg, hmac); err != nil {
		return fmt.Errorf("erreur envoi message : %v", err)
	}

	utils.Logger.Info("Message envoyé avec succès", nil)
	return nil
}

func closeConnection(writer io.Writer) {
	if closer, ok := writer.(io.Closer); ok {
		closer.Close()
	}
}
