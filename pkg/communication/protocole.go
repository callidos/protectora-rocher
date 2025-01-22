package communication

import (
	"fmt"
	"net"
	"protectora-rocher/pkg/utils"
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

var (
	messageHistory = sync.Map{}
)

func SetSessionMode(mode string) error {
	if mode != SessionEphemeral && mode != SessionPersistent {
		return fmt.Errorf("mode de session invalide")
	}
	fmt.Println("Mode de session reçu :", mode)
	return nil
}

func SendMessage(conn net.Conn, message string, sharedKey []byte, sequenceNumber uint64, duration int) error {
	if duration < 0 {
		return fmt.Errorf("la durée ne peut pas être négative")
	}

	timestamp := time.Now().Unix()
	formattedMessage := fmt.Sprintf("%d|%d|%d|%s", sequenceNumber, timestamp, duration, message)

	encryptedMessage, err := EncryptAESGCM([]byte(formattedMessage), sharedKey)
	if err != nil {
		return fmt.Errorf("erreur de chiffrement: %v", err)
	}

	hmacValue := GenerateHMAC(encryptedMessage, sharedKey)

	errChan := make(chan error, 1)
	go func() {
		_, err := fmt.Fprintf(conn, "%s|%s\n", encryptedMessage, hmacValue)
		errChan <- err
	}()

	if err := <-errChan; err != nil {
		return fmt.Errorf("erreur d'envoi du message: %v", err)
	}

	utils.LogInfo("Message envoyé avec succès", map[string]interface{}{
		"sequence": sequenceNumber,
		"duration": duration,
	})

	return nil
}

func ReceiveMessage(conn net.Conn, sharedKey []byte) (string, error) {
	resultChan := make(chan struct {
		message string
		err     error
	}, 1)

	go func() {
		defer close(resultChan)

		buffer := make([]byte, messageSizeLimit)
		n, err := conn.Read(buffer)
		if err != nil {
			resultChan <- struct {
				message string
				err     error
			}{"", fmt.Errorf("erreur de lecture du message: %v", err)}
			return
		}

		receivedMessage := strings.TrimSpace(string(buffer[:n]))
		parts := strings.SplitN(receivedMessage, "|", 2)
		if len(parts) != 2 {
			resultChan <- struct {
				message string
				err     error
			}{"", fmt.Errorf("message mal formé")}
			return
		}

		encryptedMessage := parts[0]
		receivedHMAC := parts[1]

		expectedHMAC := GenerateHMAC(encryptedMessage, sharedKey)

		if receivedHMAC != expectedHMAC {
			resultChan <- struct {
				message string
				err     error
			}{"", fmt.Errorf("HMAC invalide, message rejeté")}
			return
		}

		decryptedMessage, err := DecryptAESGCM(encryptedMessage, sharedKey)
		if err != nil {
			resultChan <- struct {
				message string
				err     error
			}{"", fmt.Errorf("erreur de déchiffrement: %v", err)}
			return
		}

		messageContent, err := validateAndStoreMessage(decryptedMessage)
		resultChan <- struct {
			message string
			err     error
		}{messageContent, err}
	}()

	result := <-resultChan
	return result.message, result.err
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
	currentTime := time.Now().Unix()
	if timestamp < (currentTime-int64(replayWindow.Seconds())) || timestamp > currentTime {
		fmt.Println("Message rejeté : horodatage invalide ou expiré")
		return true
	}

	if _, exists := messageHistory.Load(sequenceNumber); exists {
		fmt.Println("Message rejeté : numéro de séquence déjà utilisé")
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
