package communication

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// CORRECTION: Réduction de la fenêtre anti-rejeu à 30 secondes
	replayWindow     = 30 * time.Second
	messageSizeLimit = 16 * 1024 * 1024
)

// CORRECTION: Encapsuler dans une structure au lieu d'une variable globale
type MessageHistory struct {
	messages sync.Map
	mutex    sync.RWMutex
}

var globalMessageHistory = &MessageHistory{}

type envelope struct {
	Seq       uint64 `json:"seq"`
	Timestamp int64  `json:"ts"`
	Duration  int    `json:"dur"`
	Data      string `json:"data"`
}

type frame struct {
	Data string `json:"data"`
	HMAC string `json:"hmac"`
}

// CORRECTION: Méthodes thread-safe pour la gestion de l'historique
func (mh *MessageHistory) Reset() {
	mh.mutex.Lock()
	defer mh.mutex.Unlock()
	mh.messages = sync.Map{}
}

func (mh *MessageHistory) CheckAndStore(seq uint64) bool {
	_, exists := mh.messages.LoadOrStore(seq, time.Now())
	if exists {
		return false // Message déjà vu (rejeu détecté)
	}

	// Programmer la suppression après la fenêtre de rejeu
	go func(sequence uint64) {
		time.Sleep(replayWindow)
		mh.messages.Delete(sequence)
	}(seq)

	return true
}

func ResetMessageHistory() {
	globalMessageHistory.Reset()
}

func validateHMAC(message, receivedHMAC string, key []byte) bool {
	expectedMAC := computeHMAC([]byte(message), key)
	receivedMAC, err := base64.StdEncoding.DecodeString(receivedHMAC)
	return err == nil && hmac.Equal(expectedMAC, receivedMAC)
}

func SendMessage(w io.Writer, message string, key []byte, seq uint64, duration int) error {
	if duration < 0 {
		return fmt.Errorf("durée invalide (<0)")
	}

	env := envelope{
		Seq:       seq,
		Timestamp: time.Now().Unix(),
		Duration:  duration,
		Data:      message,
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal enveloppe : %w", err)
	}

	encrypted, err := EncryptAESGCM(envJSON, key)
	if err != nil {
		return fmt.Errorf("chiffrement : %w", err)
	}

	frm := frame{
		Data: encrypted,
		HMAC: GenerateHMAC(encrypted, key),
	}

	frmJSON, err := json.Marshal(frm)
	if err != nil {
		return fmt.Errorf("marshal frame : %w", err)
	}

	_, err = w.Write(append(frmJSON, '\n'))
	return err
}

func ReceiveMessage(r io.Reader, key []byte) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, messageSizeLimit))
	rawLine, err := br.ReadString('\n')
	if err != nil {
		// CORRECTION: Messages d'erreur génériques pour éviter l'information leakage
		return "", errors.New("échec de lecture du message")
	}

	raw := strings.TrimSpace(rawLine)
	if raw == "" {
		return "", errors.New("message vide")
	}

	var frm frame
	if err := json.Unmarshal([]byte(raw), &frm); err != nil {
		parts := strings.SplitN(raw, "|", 2)
		if len(parts) != 2 {
			return "", errors.New("format de message invalide")
		}
		frm = frame{Data: parts[0], HMAC: parts[1]}
	}

	if !validateHMAC(frm.Data, frm.HMAC, key) {
		return "", errors.New("authentification du message échouée")
	}

	plain, err := DecryptAESGCM(frm.Data, key)
	if err != nil {
		return "", errors.New("déchiffrement du message échoué")
	}

	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		parts := strings.SplitN(string(plain), "|", 4)
		if len(parts) != 4 {
			return "", errors.New("contenu du message invalide")
		}
		seq, _ := strconv.ParseUint(parts[0], 10, 64)
		dur, _ := strconv.Atoi(parts[2])
		env = envelope{
			Seq:       seq,
			Timestamp: mustParseInt64(parts[1]),
			Duration:  dur,
			Data:      parts[3],
		}
	}

	if err := validateMessage(env); err != nil {
		return "", err
	}

	return env.Data, nil
}

// CORRECTION: Validation renforcée avec des messages d'erreur génériques
func validateMessage(env envelope) error {
	now := time.Now().Unix()

	// Vérification de la fenêtre temporelle (réduite)
	windowSeconds := int64(replayWindow.Seconds())
	if env.Timestamp < now-windowSeconds || env.Timestamp > now+5 { // +5 sec de tolérance pour la dérive d'horloge
		return errors.New("message hors de la fenêtre temporelle autorisée")
	}

	// Vérification de l'expiration
	if env.Duration > 0 && now > env.Timestamp+int64(env.Duration) {
		return errors.New("message expiré")
	}

	// CORRECTION: Utiliser la structure thread-safe pour l'anti-rejeu
	if !globalMessageHistory.CheckAndStore(env.Seq) {
		return errors.New("message déjà traité")
	}

	return nil
}

func mustParseInt64(s string) int64 {
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}
