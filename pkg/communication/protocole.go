package communication

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const replayWindow = 5 * time.Minute

var (
	messageHistory = make(map[string]time.Time)
	mu             sync.Mutex
)

// SendMessage envoie un message sécurisé via TCP
func SendMessage(conn net.Conn, message string, sharedKey []byte, sequenceNumber uint64) error {
	timestamp := time.Now().Unix()
	formattedMessage := fmt.Sprintf("%d|%d|%s", sequenceNumber, timestamp, message)

	encryptedMessage, err := EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmac := GenerateHMAC(encryptedMessage, sharedKey)

	_, err = fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmac)
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message: %v", err)
	}

	return nil
}

// ReceiveMessage reçoit et valide un message sécurisé via TCP
func ReceiveMessage(conn net.Conn, sharedKey []byte) (string, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("erreur de lecture du message: %v", err)
	}

	receivedMessage := strings.TrimSpace(string(buffer[:n]))
	parts := strings.SplitN(receivedMessage, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("message mal formé")
	}

	encryptedMessage := parts[0]
	receivedHMAC := parts[1]

	expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)
	if receivedHMAC != expectedHMAC {
		return "", fmt.Errorf("HMAC invalide, message rejeté")
	}

	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return "", fmt.Errorf("erreur de déchiffrement: %v", err)
	}

	return validateAndStoreMessage(decryptedMessage)
}

// Fonction privée pour valider et stocker les messages (anti-rejeu)
func validateAndStoreMessage(message []byte) (string, error) {
	messageParts := strings.SplitN(string(message), "|", 3)
	if len(messageParts) != 3 {
		return "", fmt.Errorf("format du message incorrect")
	}

	sequenceNumber := messageParts[0]
	timestampStr := messageParts[1]
	messageContent := messageParts[2]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("horodatage invalide")
	}

	if isReplayAttack(sequenceNumber, timestamp) {
		return "", fmt.Errorf("message rejeté en raison d'une attaque par rejeu détectée")
	}

	return messageContent, nil
}

// Vérifie si un message est un rejet (replay) via son horodatage et son numéro de séquence
func isReplayAttack(sequenceNumber string, timestamp int64) bool {
	mu.Lock()
	defer mu.Unlock()

	currentTime := time.Now().Unix()
	// Vérifier si le timestamp est trop vieux ou trop futur
	if timestamp < (currentTime-int64(replayWindow.Seconds())) || timestamp > currentTime {
		fmt.Println("Message rejeté : horodatage invalide ou expiré")
		return true
	}

	// Vérifier si la séquence existe déjà
	if _, exists := messageHistory[sequenceNumber]; exists {
		fmt.Println("Message rejeté : numéro de séquence déjà utilisé")
		return true
	}

	// Enregistrer cette séquence pour la bloquer plus tard
	messageHistory[sequenceNumber] = time.Now()
	return false
}

// ResetMessageHistory réinitialise l'historique des messages pour les tests.
func ResetMessageHistory() {
	mu.Lock()
	defer mu.Unlock()
	messageHistory = make(map[string]time.Time)
}
