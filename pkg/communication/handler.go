package communication

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/callidos/protectora-rocher/pkg/utils"
)

const (
	bufferSize = 1024 * 1024
)

// CORRECTION: Amélioration de la gestion d'erreurs avec des codes et messages génériques
type SecureError struct {
	Code    int
	Message string
	Wrapped error
}

func (e *SecureError) Error() string {
	// CORRECTION: Ne pas exposer l'erreur wrappée pour éviter l'information leakage
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Messages d'erreur génériques pour éviter l'information leakage
var (
	ErrConnectionFailed     = &SecureError{Code: 1000, Message: "Échec de connexion"}
	ErrAuthenticationFailed = &SecureError{Code: 2000, Message: "Échec d'authentification"}
	ErrProcessingFailed     = &SecureError{Code: 3000, Message: "Échec de traitement"}
	ErrInvalidInput         = &SecureError{Code: 4000, Message: "Entrée invalide"}
)

func securityError(errorType *SecureError, err error) *SecureError {
	return &SecureError{Code: errorType.Code, Message: errorType.Message, Wrapped: err}
}

func HandleConnection(r io.Reader, w io.Writer, sharedKey []byte) {
	utils.Logger.Info("Nouvelle connexion", nil)

	limited := io.LimitReader(r, messageSizeLimit)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	username, err := readUsername(scanner)
	if err != nil {
		// CORRECTION: Log détaillé côté serveur, message générique côté client
		utils.Logger.Warning("Lecture username échouée", map[string]interface{}{"error": err})
		sendErrorResponse(w, ErrConnectionFailed)
		return
	}

	if err := sendWelcomeMessage(w, sharedKey, username); err != nil {
		utils.Logger.Error("Envoi welcome KO", map[string]interface{}{"err": err})
		return
	}

	msgChan := make(chan string)
	done := make(chan struct{})
	go processIncomingMessages(scanner, msgChan, done, username)

	for {
		select {
		case raw := <-msgChan:
			if err := processMessage(raw, sharedKey, w, username); err != nil {
				// CORRECTION: Log détaillé côté serveur, réponse générique côté client
				utils.Logger.Error("Traitement message KO", map[string]interface{}{
					"user":  username,
					"error": err,
				})
				sendErrorResponse(w, ErrProcessingFailed)
			}
		case <-done:
			closeConnection(w)
			return
		}
	}
}

func readUsername(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		return "", securityError(ErrConnectionFailed, scanner.Err())
	}
	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		return "", securityError(ErrInvalidInput, nil)
	}
	// CORRECTION: Validation basique du nom d'utilisateur
	if len(username) > 64 || len(username) < 1 {
		return "", securityError(ErrInvalidInput, nil)
	}
	return username, nil
}

func processIncomingMessages(scanner *bufio.Scanner, ch chan<- string, done chan<- struct{}, user string) {
	defer func() {
		done <- struct{}{}
	}()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "FIN_SESSION" {
			utils.Logger.Info("Fin de session demandée", map[string]interface{}{"user": user})
			return
		}
		ch <- line
	}

	// CORRECTION: Logger l'erreur de scan si elle existe
	if err := scanner.Err(); err != nil {
		utils.Logger.Error("Erreur de lecture", map[string]interface{}{
			"user":  user,
			"error": err,
		})
	}
}

func processMessage(raw string, key []byte, w io.Writer, user string) error {
	var frm frame
	if err := json.Unmarshal([]byte(raw), &frm); err != nil {
		parts := strings.SplitN(raw, "|", 2)
		if len(parts) != 2 {
			return securityError(ErrAuthenticationFailed, err)
		}
		frm = frame{Data: parts[0], HMAC: parts[1]}
	}

	wantMAC := computeHMAC([]byte(frm.Data), key)
	gotMAC, err := base64.StdEncoding.DecodeString(frm.HMAC)
	if err != nil {
		return securityError(ErrAuthenticationFailed, err)
	}
	if !hmac.Equal(wantMAC, gotMAC) {
		return securityError(ErrAuthenticationFailed, nil)
	}

	plain, err := DecryptAESGCM(frm.Data, key)
	if err != nil {
		return securityError(ErrAuthenticationFailed, err)
	}

	// CORRECTION: Validation de la taille du message déchiffré
	if len(plain) > 10*1024 { // 10KB max pour les messages texte
		return securityError(ErrInvalidInput, nil)
	}

	utils.Logger.Info("Message reçu", map[string]interface{}{
		"user": user,
		"size": len(plain),
		// Ne pas logger le contenu du message pour la confidentialité
	})

	return sendAcknowledgment(w, key)
}

func sendWelcomeMessage(w io.Writer, key []byte, user string) error {
	return SendMessage(
		w,
		fmt.Sprintf("Bienvenue %s sur le serveur sécurisé.", user),
		key,
		0,
		0,
	)
}

func sendAcknowledgment(w io.Writer, key []byte) error {
	return SendMessage(w, "Message reçu avec succès.", key, 0, 0)
}

// CORRECTION: Ajouter une fonction pour envoyer des réponses d'erreur génériques
func sendErrorResponse(w io.Writer, secErr *SecureError) {
	// Envoyer une réponse d'erreur générique sans détails
	errorMsg := fmt.Sprintf("Erreur %d: %s", secErr.Code, secErr.Message)
	if _, err := w.Write([]byte(errorMsg + "\n")); err != nil {
		utils.Logger.Error("Échec envoi réponse d'erreur", map[string]interface{}{
			"error": err,
		})
	}
}

func closeConnection(w io.Writer) {
	if closer, ok := w.(io.Closer); ok {
		_ = closer.Close()
	}
}
