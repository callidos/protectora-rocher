package tests

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// clef partagée
var key = []byte("thisisaverysecurekey!")

// -----------------------------------------------------------------------------
// Structures de transport
// -----------------------------------------------------------------------------

type frame struct {
	Data string `json:"data"`
	HMAC string `json:"hmac"`
}

type envelope struct {
	Data string `json:"data"`
}

// -----------------------------------------------------------------------------
// Helpers communs
// -----------------------------------------------------------------------------

// fabrique une frame chiffrée (client → serveur) contenant msg (texte brut)
func clientFrame(msg string, key []byte) string {
	cipher, _ := communication.EncryptAESGCM([]byte(msg), key)
	frm := frame{
		Data: cipher,
		HMAC: communication.GenerateHMAC(cipher, key),
	}
	b, _ := json.Marshal(frm)
	return string(b) + "\n"
}

// renvoie la première ligne JSON du flux
func firstJSONLine(s string) string {
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.HasPrefix(l, "{") {
			return l
		}
	}
	return ""
}

// déchiffre une frame et renvoie le message (env.Data ou texte brut)
func decryptFrameAndExtractData(line string, key []byte) (string, error) {
	var frm frame
	if err := json.Unmarshal([]byte(line), &frm); err != nil {
		return "", err
	}
	exp := communication.GenerateHMAC(frm.Data, key)
	if !hmac.Equal([]byte(exp), []byte(frm.HMAC)) {
		return "", fmt.Errorf("HMAC mismatch")
	}
	plain, err := communication.DecryptAESGCM(frm.Data, key)
	if err != nil {
		return "", err
	}
	var env envelope
	if json.Unmarshal(plain, &env) == nil && env.Data != "" {
		return env.Data, nil
	}
	return string(plain), nil
}

// compte les ACK “Message reçu avec succès.”
func countAck(output string, key []byte) int {
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(output), "\n") {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		if msg, _ := decryptFrameAndExtractData(l, key); msg == "Message reçu avec succès." {
			n++
		}
	}
	return n
}

// vérifie le welcome
func checkWelcome(t *testing.T, output string, key []byte, user string) {
	line := firstJSONLine(output)
	if line == "" {
		t.Fatalf("aucune frame JSON trouvée : %q", output)
	}
	msg, err := decryptFrameAndExtractData(line, key)
	if err != nil {
		t.Fatalf("décryptage KO : %v", err)
	}
	want := "Bienvenue " + user + " sur le serveur sécurisé."
	if msg != want {
		t.Fatalf("welcome diffère : exp=%q got=%q", want, msg)
	}
}

// -----------------------------------------------------------------------------
// TESTS
// -----------------------------------------------------------------------------

func TestHandleConnection(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("testuser\nFIN_SESSION\n"))

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	select {
	case <-done:
		checkWelcome(t, mock.Buffer.String(), key, "testuser")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRejectCorruptedMessage(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("testuser\n"))

	// frame avec HMAC corrompu
	cipher, _ := communication.EncryptAESGCM([]byte("Hello"), key)
	h := communication.GenerateHMAC(cipher, key)
	h = h[:len(h)-1] + "A" // corruption

	bad, _ := json.Marshal(frame{Data: cipher, HMAC: h})
	mock.Write(append(bad, '\n'))
	mock.Write([]byte("FIN_SESSION\n"))

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	<-done

	if countAck(mock.Buffer.String(), key) != 0 {
		t.Fatal("ACK reçu alors que le message est corrompu")
	}
}

func TestHandleConnectionWithError(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("\n")) // pseudo vide

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	<-done

	line := firstJSONLine(mock.Buffer.String())
	if line == "" {
		// connexion fermée sans envoi (comportement acceptable)
		return
	}
	msg, err := decryptFrameAndExtractData(line, key)
	if err != nil {
		t.Fatalf("décryptage KO : %v", err)
	}
	if msg != "Erreur: Nom d'utilisateur vide" {
		t.Fatalf("Attendu message d'erreur, obtenu %q", msg)
	}
}

func TestHandleConnectionSessionDuration(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("testuser\nFIN_SESSION\n"))

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("La session aurait dû se terminer")
	}
}

func TestHandleMultipleMessages(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("testuser\n"))
	mock.Write([]byte(clientFrame("Message 1", key)))
	mock.Write([]byte(clientFrame("Message 2", key)))
	mock.Write([]byte(clientFrame("Message 3", key)))
	mock.Write([]byte("FIN_SESSION\n"))

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	<-done

	if acks := countAck(mock.Buffer.String(), key); acks != 3 {
		t.Fatalf("Attendu 3 ACK, reçu %d", acks)
	}
}

func TestInvalidUsernameHandling(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("\n")) // pseudo vide

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	<-done

	for _, l := range strings.Split(strings.TrimSpace(mock.Buffer.String()), "\n") {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		msg, _ := decryptFrameAndExtractData(l, key)
		if strings.HasPrefix(msg, "Bienvenue") {
			t.Fatal("La session ne doit pas démarrer avec un pseudo vide")
		}
	}
}

func TestEmptyMessageHandling(t *testing.T) {
	mock := &MockConnection{}
	mock.Write([]byte("testuser\n"))
	mock.Write([]byte(clientFrame("", key))) // message vide
	mock.Write([]byte("FIN_SESSION\n"))

	done := make(chan struct{})
	go func() {
		communication.HandleConnection(mock, mock, key)
		close(done)
	}()
	<-done

	if countAck(mock.Buffer.String(), key) != 0 {
		t.Fatal("ACK reçu alors que le message est vide")
	}
}
