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
	replayWindow     = 5 * time.Minute
	messageSizeLimit = 8192
)

var messageHistory sync.Map

func SendMessage(writer io.Writer, message string, sharedKey []byte, sequenceNumber uint64, duration int) error {
	if duration < 0 {
		return fmt.Errorf("durée invalide")
	}

	formattedMessage := fmt.Sprintf("%d|%d|%d|%s", sequenceNumber, time.Now().Unix(), duration, message)

	encryptedMessage, err := EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %w", err)
	}

	if _, err := fmt.Fprintf(writer, "%s|%s\n", encryptedMessage, GenerateHMAC(encryptedMessage, sharedKey)); err != nil {
		return fmt.Errorf("erreur d'envoi du message: %w", err)
	}

	return nil
}

func ReceiveMessage(reader io.Reader, sharedKey []byte) (string, error) {
	buffer := make([]byte, messageSizeLimit)
	n, err := reader.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("erreur de lecture: %w", err)
	}

	message := strings.TrimSpace(string(buffer[:n]))
	parts := strings.SplitN(message, "|", 2)
	if len(parts) != 2 || !validateHMAC(parts[0], parts[1], sharedKey) {
		return "", fmt.Errorf("message invalide ou corrompu")
	}

	return validateAndStoreMessage(parts[0], sharedKey)
}

func validateAndStoreMessage(encryptedMessage string, sharedKey []byte) (string, error) {
	decrypted, err := DecryptAESGCM(encryptedMessage, sharedKey)
	if err != nil {
		return "", fmt.Errorf("erreur de déchiffrement: %w", err)
	}

	parts := strings.SplitN(string(decrypted), "|", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("format du message incorrect")
	}

	if err := validateMessage(parts[0], parts[1], parts[2]); err != nil {
		return "", err
	}

	return parts[3], nil
}

func validateMessage(sequence, timestampStr, durationStr string) error {
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil || isExpired(timestamp, durationStr) || isReplayAttack(sequence, timestamp) {
		return fmt.Errorf("message invalide")
	}
	return nil
}

func isExpired(timestamp int64, durationStr string) bool {
	duration, err := strconv.Atoi(durationStr)
	return err != nil || (duration > 0 && time.Now().Unix() > timestamp+int64(duration))
}

func isReplayAttack(sequence string, timestamp int64) bool {
	now := time.Now().Unix()
	if timestamp < now-int64(replayWindow.Seconds()) || timestamp > now {
		return true
	}
	if _, exists := messageHistory.Load(sequence); exists {
		return true
	}
	messageHistory.Store(sequence, time.Now())
	go func(seq string) {
		time.Sleep(replayWindow)
		messageHistory.Delete(seq)
	}(sequence)
	return false
}

func ResetMessageHistory() {
	messageHistory = sync.Map{}
}

func validateHMAC(message, receivedHMAC string, key []byte) bool {
	return GenerateHMAC(message, key) == receivedHMAC
}
