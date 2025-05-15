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
	replayWindow     = 5 * time.Minute
	messageSizeLimit = 16 * 1024 * 1024
)

var messageHistory sync.Map

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

func ResetMessageHistory() { messageHistory = sync.Map{} }

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
		return "", fmt.Errorf("lecture : %w", err)
	}
	raw := strings.TrimSpace(rawLine)
	if raw == "" {
		return "", errors.New("message vide")
	}

	var frm frame
	if err := json.Unmarshal([]byte(raw), &frm); err != nil {
		parts := strings.SplitN(raw, "|", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("frame invalide (JSON ou « | »)")
		}
		frm = frame{Data: parts[0], HMAC: parts[1]}
	}

	if !validateHMAC(frm.Data, frm.HMAC, key) {
		return "", errors.New("HMAC invalide ou message corrompu")
	}

	plain, err := DecryptAESGCM(frm.Data, key)
	if err != nil {
		return "", fmt.Errorf("déchiffrement : %w", err)
	}

	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		parts := strings.SplitN(string(plain), "|", 4)
		if len(parts) != 4 {
			return "", errors.New("enveloppe déchiffrée invalide")
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

func validateMessage(env envelope) error {
	now := time.Now().Unix()

	if env.Timestamp < now-int64(replayWindow.Seconds()) || env.Timestamp > now {
		return errors.New("horodatage hors fenêtre autorisée")
	}
	if env.Duration > 0 && now > env.Timestamp+int64(env.Duration) {
		return errors.New("message expiré")
	}
	if _, found := messageHistory.LoadOrStore(env.Seq, struct{}{}); found {
		return errors.New("rejeu détecté")
	}
	go func(seq uint64) {
		time.Sleep(replayWindow)
		messageHistory.Delete(seq)
	}(env.Seq)

	return nil
}

func mustParseInt64(s string) int64 {
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}
