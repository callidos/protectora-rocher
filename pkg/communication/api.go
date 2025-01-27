package communication

import (
	"errors"
	"io"
)

// EncryptMessage chiffre un message avec une clé partagée.
// - Paramètres:
//   - message: texte clair à chiffrer.
//   - key: clé partagée (32 octets).
//
// - Retour: message chiffré (base64) ou erreur.
func EncryptMessage(message string, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("la clé ne peut pas être vide")
	}
	return EncryptAESGCM([]byte(message), key)
}

// DecryptMessage déchiffre un message chiffré.
// - Paramètres:
//   - encryptedMessage: message chiffré (base64).
//   - key: clé partagée (32 octets).
//
// - Retour: message en clair ou erreur.
func DecryptMessage(encryptedMessage string, key []byte) (string, error) {
	decrypted, err := DecryptAESGCM(encryptedMessage, key)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// SendSecureMessage envoie un message sécurisé via un writer.
// - Paramètres:
//   - writer: connexion réseau ou fichier pour envoyer les données.
//   - message: texte clair à envoyer.
//   - key: clé partagée (32 octets).
//   - seqNum: numéro de séquence unique.
//   - duration: durée avant expiration (secondes).
//
// - Retour: erreur si l'envoi échoue.
func SendSecureMessage(writer io.Writer, message string, key []byte, seqNum uint64, duration int) error {
	return SendMessage(writer, message, key, seqNum, duration)
}

// ReceiveSecureMessage reçoit un message sécurisé via un reader.
// - Paramètres:
//   - reader: connexion réseau ou fichier pour recevoir les données.
//   - key: clé partagée (32 octets).
//
// - Retour: message en clair ou erreur.
func ReceiveSecureMessage(reader io.Reader, key []byte) (string, error) {
	return ReceiveMessage(reader, key)
}

// HandleNewConnection gère une nouvelle connexion client en boucle.
// - Paramètres:
//   - reader: connexion entrante (client).
//   - writer: connexion sortante (serveur).
//   - sharedKey: clé partagée pour l'échange sécurisé.
func HandleNewConnection(reader io.Reader, writer io.Writer, sharedKey []byte) {
	HandleConnection(reader, writer, sharedKey)
}

// PerformKeyExchange effectue un échange de clés sécurisé avec le protocole Kyber.
// - Paramètres:
//   - conn: connexion réseau bidirectionnelle.
//   - privKey: clé privée Ed25519 (32 octets).
//
// - Retour: canal recevant le résultat de l'échange de clé, ou erreur.
func PerformKeyExchange(conn io.ReadWriter, privKey []byte) (<-chan KeyExchangeResult, error) {
	return PerformAuthenticatedKeyExchange(conn, privKey)
}

// InitiateSecureCall démarre un appel vocal sécurisé.
// - Paramètres:
//   - conn: connexion réseau bidirectionnelle.
//   - key: clé partagée (32 octets).
//
// - Retour: erreur si l'appel ne peut pas être initié.
func InitiateSecureCall(conn io.ReadWriter, key []byte) error {
	return StartSecureCall(conn, key)
}

// TerminateSecureCall met fin à un appel vocal sécurisé.
// - Paramètres:
//   - conn: connexion réseau bidirectionnelle.
//   - key: clé partagée (32 octets).
func TerminateSecureCall(conn io.ReadWriter, key []byte) {
	StopSecureCall(conn, key)
}

// ResetSecurityState réinitialise l'état de sécurité du système, supprimant les clés et l'historique des messages.
func ResetSecurityState() {
	ResetMessageHistory()
	ResetKeyExchangeState()
}
