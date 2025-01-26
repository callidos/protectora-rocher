package communication

import (
	"fmt"
	"io"
)

var validModes = map[string]bool{
	"production":  true,
	"development": true,
	"testMode":    true, // Ajout du mode test
}

// InitializeSession initialise la session en définissant le mode.
func InitializeSession(mode string) error {
	if mode != SessionEphemeral && mode != SessionPersistent {
		return fmt.Errorf("mode de session invalide: %s", mode)
	}
	fmt.Println("Session mode initialisé:", mode)
	return nil
}

func EncryptMessage(message string, key []byte) (string, error) {
	return EncryptAESGCM([]byte(message), key)
}

func DecryptMessage(encryptedMessage string, key []byte) (string, error) {
	decrypted, err := DecryptAESGCM(encryptedMessage, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func SendSecureMessage(writer io.Writer, message string, key []byte, seqNum uint64, duration int) error {
	return SendMessage(writer, message, key, seqNum, duration)
}

func ReceiveSecureMessage(reader io.Reader, key []byte) (string, error) {
	return ReceiveMessage(reader, key)
}

func PerformKeyExchange(conn io.ReadWriter) error {
	return performKyberDilithiumKeyExchange(conn)
}

func ResetSecurityState() {
	ResetMessageHistory()
	ResetKeyExchangeState()
}
