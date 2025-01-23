package communication

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	replayWindow      = 5 * time.Minute
	messageSizeLimit  = 8192
	SessionEphemeral  = "ephemeral"
	SessionPersistent = "persistent"
)

var messageHistory sync.Map

func SetSessionMode(mode string) error {
	if mode != SessionEphemeral && mode != SessionPersistent {
		return fmt.Errorf("mode de session invalide")
	}
	return nil
}

func SendMessage(writer io.Writer, message string, sharedKey []byte, sequenceNumber uint64, duration int) error {
	if duration < 0 {
		return fmt.Errorf("durée invalide")
	}

	formattedMessage := fmt.Sprintf("%d|%d|%d|%s", sequenceNumber, time.Now().Unix(), duration, message)

	encryptedMessage, err := EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	_, err = fmt.Fprintf(writer, "%s|%s\n", encryptedMessage, GenerateHMAC(encryptedMessage, sharedKey))
	if err != nil {
		return fmt.Errorf("erreur d'envoi du message: %v", err)
	}

	return nil
}

func ReceiveMessage(reader io.Reader, sharedKey []byte) (string, error) {
	buffer := make([]byte, messageSizeLimit)
	n, err := reader.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("erreur de lecture: %v", err)
	}

	parts := strings.SplitN(strings.TrimSpace(string(buffer[:n])), "|", 2)
	if len(parts) != 2 || GenerateHMAC(parts[0], sharedKey) != parts[1] {
		return "", fmt.Errorf("message invalide ou corrompu")
	}

	return validateAndStoreMessage(parts[0], sharedKey)
}

func validateAndStoreMessage(encryptedMessage string, sharedKey []byte) (string, error) {
	decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return "", fmt.Errorf("erreur de déchiffrement: %v", err)
	}

	parts := strings.SplitN(string(decryptedMessage), "|", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("format du message incorrect")
	}

	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || isExpired(timestamp, parts[2]) || isReplayAttack(parts[0], timestamp) {
		return "", fmt.Errorf("message invalide")
	}

	return parts[3], nil
}

func isExpired(timestamp int64, durationStr string) bool {
	duration, err := strconv.Atoi(durationStr)
	if err != nil || (duration > 0 && time.Now().Unix() > timestamp+int64(duration)) {
		return true
	}
	return false
}

func isReplayAttack(sequenceNumber string, timestamp int64) bool {
	now := time.Now().Unix()
	if timestamp < now-int64(replayWindow.Seconds()) || timestamp > now {
		return true
	}
	if _, exists := messageHistory.Load(sequenceNumber); exists {
		return true
	}
	messageHistory.Store(sequenceNumber, time.Now())
	go func(seq string) {
		time.Sleep(replayWindow)
		messageHistory.Delete(seq)
	}(sequenceNumber)
	return false
}

func ResetMessageHistory() {
	messageHistory = sync.Map{}
}
