package communication

import (
	"io"
)

func InitializeSession(mode string) error {
	return SetSessionMode(mode)
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

func HandleNewConnection(reader io.Reader, writer io.Writer, sharedKey []byte) {
	HandleConnection(reader, writer, sharedKey)
}

func PerformKeyExchange(conn io.ReadWriter, privKey []byte, pubKey []byte) (<-chan KeyExchangeResult, error) {
	return PerformAuthenticatedKeyExchange(conn, privKey)

}

func InitiateSecureCall(conn io.ReadWriter, key []byte) error {
	return StartSecureCall(conn, key)
}

func TerminateSecureCall(conn io.ReadWriter, key []byte) {
	StopSecureCall(conn, key)
}

func ResetSecurityState() {
	ResetMessageHistory()
	ResetKeyExchangeState()
}
