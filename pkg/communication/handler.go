package communication

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"protectora-rocher/pkg/utils"
	"strings"
)

const (
	bufferSize = 1024 * 1024
)

type SecureError struct {
	Code    int
	Message string
	Wrapped error
}

func (e *SecureError) Error() string {
	if e.Wrapped == nil {
		return fmt.Sprintf("[%d] %s", e.Code, e.Message)
	}
	return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Wrapped)
}

func securityError(code int, msg string, err error) *SecureError {
	return &SecureError{Code: code, Message: msg, Wrapped: err}
}

func HandleConnection(r io.Reader, w io.Writer, sharedKey []byte) {
	utils.Logger.Info("Nouvelle connexion", nil)

	limited := io.LimitReader(r, messageSizeLimit)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, bufferSize), bufferSize)

	username, err := readUsername(scanner)
	if err != nil {
		utils.Logger.Warning(err.Error(), nil)
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
				utils.Logger.Error("Traitement message KO", map[string]interface{}{"err": err})
			}
		case <-done:
			closeConnection(w)
			return
		}
	}
}

func readUsername(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		return "", securityError(1001, "Impossible de lire le nom d’utilisateur", scanner.Err())
	}
	username := strings.TrimSpace(scanner.Text())
	if username == "" {
		return "", securityError(1002, "Nom d’utilisateur vide", nil)
	}
	return username, nil
}

func processIncomingMessages(scanner *bufio.Scanner, ch chan<- string, done chan<- struct{}, user string) {
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "FIN_SESSION" {
			utils.Logger.Info("Fin de session demandée", map[string]interface{}{"user": user})
			done <- struct{}{}
			return
		}
		ch <- line
	}
	done <- struct{}{}
}

func processMessage(raw string, key []byte, w io.Writer, user string) error {
	var frm frame
	if err := json.Unmarshal([]byte(raw), &frm); err != nil {
		parts := strings.SplitN(raw, "|", 2)
		if len(parts) != 2 {
			return securityError(2001, "Frame invalide", err)
		}
		frm = frame{Data: parts[0], HMAC: parts[1]}
	}

	wantMAC := computeHMAC([]byte(frm.Data), key)
	gotMAC, err := base64.StdEncoding.DecodeString(frm.HMAC)
	if err != nil {
		return securityError(2002, "HMAC base64 invalide", err)
	}
	if !hmac.Equal(wantMAC, gotMAC) {
		return securityError(2003, "HMAC incohérent", nil)
	}

	plain, err := DecryptAESGCM(frm.Data, key)
	if err != nil {
		return securityError(2004, "Déchiffrement échoué", err)
	}

	utils.Logger.Info("Message reçu", map[string]interface{}{
		"user": user,
		"msg":  string(plain),
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

func closeConnection(w io.Writer) {
	if closer, ok := w.(io.Closer); ok {
		_ = closer.Close()
	}
}
