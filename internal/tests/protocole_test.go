package tests

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// clef partagée pour tout le fichier
var sharedKey = []byte("securekey!")

// -----------------------------------------------------------------------------
// ENVOI
// -----------------------------------------------------------------------------

func TestSendMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := communication.SendMessage(&buf, "hello JSON", sharedKey, 1, 42); err != nil {
		t.Fatalf("échec SendMessage : %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("rien n'a été écrit")
	}
}

// -----------------------------------------------------------------------------
// RÉCEPTION
// -----------------------------------------------------------------------------

func TestReceiveMessage(t *testing.T) {
	var buf bytes.Buffer
	want := "payload-test"
	_ = communication.SendMessage(&buf, want, sharedKey, 7, 60)

	got, err := communication.ReceiveMessage(&buf, sharedKey)
	if err != nil || got != want {
		t.Fatalf("voulu : %q, obtenu : %q, err : %v", want, got, err)
	}
}

// -----------------------------------------------------------------------------
// SÉCURITÉ : REPLAY
// -----------------------------------------------------------------------------

func TestReplayAttack(t *testing.T) {
	communication.ResetMessageHistory()

	var buf bytes.Buffer
	_ = communication.SendMessage(&buf, "replay", sharedKey, 99, 0)

	if _, err := communication.ReceiveMessage(&buf, sharedKey); err != nil {
		t.Fatalf("1ʳᵉ réception KO : %v", err)
	}
	if _, err := communication.ReceiveMessage(&buf, sharedKey); err == nil {
		t.Fatal("attaque replay non détectée")
	}
}

// -----------------------------------------------------------------------------
// SÉCURITÉ : EXPIRATION
// -----------------------------------------------------------------------------

func TestExpiredMessage(t *testing.T) {
	env := map[string]interface{}{
		"seq":  1,
		"ts":   time.Now().Unix() - 1000,
		"dur":  10,
		"data": "obsolète",
	}
	envJSON, _ := json.Marshal(env)
	encrypted, _ := communication.EncryptAESGCM(envJSON, sharedKey)

	frm := map[string]string{
		"data": encrypted,
		"hmac": communication.GenerateHMAC(encrypted, sharedKey),
	}
	frmJSON, _ := json.Marshal(frm)
	buf := bytes.NewBuffer(append(frmJSON, '\n'))

	if _, err := communication.ReceiveMessage(buf, sharedKey); err == nil {
		t.Fatal("message expiré accepté")
	}
}

// -----------------------------------------------------------------------------
// SÉCURITÉ : CORRUPTION HMAC
// -----------------------------------------------------------------------------

func TestCorruptedMessage(t *testing.T) {
	var buf bytes.Buffer
	_ = communication.SendMessage(&buf, "corrompu", sharedKey, 5, 0)

	raw := buf.String()
	raw = raw[:len(raw)-2] + "A\n" // corruption du HMAC

	buf.Reset()
	buf.WriteString(raw)

	if _, err := communication.ReceiveMessage(&buf, sharedKey); err == nil {
		t.Fatal("HMAC invalide accepté")
	}
}

// -----------------------------------------------------------------------------
// SÉCURITÉ : FORMAT MALFORMÉ
// -----------------------------------------------------------------------------

func TestMalformedMessage(t *testing.T) {
	buf := bytes.NewBufferString(`{ "data": "noHmac" }` + "\n")
	if _, err := communication.ReceiveMessage(buf, sharedKey); err == nil {
		t.Fatal("message malformé accepté")
	}
}

// -----------------------------------------------------------------------------
// PERFORMANCE (séquentiel aller-retour)
// -----------------------------------------------------------------------------

func TestMessagePerformance(t *testing.T) {
	communication.ResetMessageHistory()

	start := time.Now()
	for i := 0; i < 1000; i++ {
		var buf bytes.Buffer
		seq := uint64(10_000 + i)
		if err := communication.SendMessage(&buf, "bench", sharedKey, seq, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := communication.ReceiveMessage(&buf, sharedKey); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("Time for 1000 round-trips: %v", time.Since(start))
}

// -----------------------------------------------------------------------------
// PERFORMANCE (concurrent, aller-retour)
// -----------------------------------------------------------------------------

func TestMessagePerformanceConcurrent(t *testing.T) {
	communication.ResetMessageHistory()

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < 1000; i++ {
		i := i // capture
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			seq := uint64(20_000 + i)
			_ = communication.SendMessage(&buf, "bench", sharedKey, seq, 0)
			_, _ = communication.ReceiveMessage(&buf, sharedKey)
		}()
	}
	wg.Wait()
	t.Logf("Time for 1000 concurrent round-trips: %v", time.Since(start))
}
