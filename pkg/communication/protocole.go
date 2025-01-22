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

const (
	SessionEphemeral  = "ephemeral"
	SessionPersistent = "persistent"
)

func SetSessionMode(mode string) error {
	if mode != SessionEphemeral && mode != SessionPersistent {
		return fmt.Errorf("mode de session invalide")
	}
	fmt.Println("Mode de session reçu :", mode)
	return nil
}

func SendMessage(conn net.Conn, message string, sharedKey []byte, sequenceNumber uint64, duration int) error {
	timestamp := time.Now().Unix()
	formattedMessage := fmt.Sprintf("%d|%d|%d|%s", sequenceNumber, timestamp, duration, message)

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

func validateAndStoreMessage(message []byte) (string, error) {
	messageParts := strings.SplitN(string(message), "|", 4)
	if len(messageParts) != 4 {
		return "", fmt.Errorf("format du message incorrect")
	}

	sequenceNumber := messageParts[0]
	timestampStr := messageParts[1]
	durationStr := messageParts[2]
	messageContent := messageParts[3]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("horodatage invalide")
	}

	duration, err := strconv.Atoi(durationStr)
	if err != nil {
		return "", fmt.Errorf("durée invalide")
	}

	if duration > 0 && time.Now().Unix() > (timestamp+int64(duration)) {
		return "", fmt.Errorf("message expiré, rejeté")
	}

	if isReplayAttack(sequenceNumber, timestamp) {
		return "", fmt.Errorf("message rejeté en raison d'une attaque par rejeu détectée")
	}

	return messageContent, nil
}

func isReplayAttack(sequenceNumber string, timestamp int64) bool {
	mu.Lock()
	defer mu.Unlock()

	currentTime := time.Now().Unix()
	if timestamp < (currentTime-int64(replayWindow.Seconds())) || timestamp > currentTime {
		fmt.Println("Message rejeté : horodatage invalide ou expiré")
		return true
	}

	if _, exists := messageHistory[sequenceNumber]; exists {
		fmt.Println("Message rejeté : numéro de séquence déjà utilisé")
		return true
	}

	messageHistory[sequenceNumber] = time.Now()
	return false
}

func ResetMessageHistory() {
	mu.Lock()
	defer mu.Unlock()
	messageHistory = make(map[string]time.Time)
}
