package tests

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/callidos/protectora-rocher/pkg/communication"
)

// CORRECTION: Générer une clé de session partagée pour les tests
var sharedSessionKey = generateTestSessionKey()

func generateTestSessionKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func TestNewAudioProtocol(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}

	// CORRECTION: Passer la clé de session partagée
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole audio : %v", err)
	}

	if protocol == nil {
		t.Fatal("Le protocole ne doit pas être nil")
	}

	// Vérification de l'état initial
	if protocol.IsActive() {
		t.Error("Le protocole ne doit pas être actif au début")
	}
}

func TestNewAudioProtocolWithNilConnection(t *testing.T) {
	_, err := communication.NewAudioProtocol(nil, sharedSessionKey)
	if err == nil {
		t.Error("La création avec une connexion nil doit échouer")
	}
}

// CORRECTION: Test avec clé insuffisante
func TestNewAudioProtocolWithInsufficientKey(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	shortKey := make([]byte, 16) // Clé trop courte

	_, err := communication.NewAudioProtocol(mockConn, shortKey)
	if err == nil {
		t.Error("La création avec une clé insuffisante doit échouer")
	}
}

func TestStartStopSecureCall(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	// Test de démarrage d'appel
	err = protocol.StartSecureCall()
	if err != nil {
		t.Errorf("Échec de démarrage de l'appel : %v", err)
	}

	if !protocol.IsActive() {
		t.Error("Le protocole doit être actif après le démarrage")
	}

	// Test d'arrêt d'appel
	err = protocol.StopSecureCall()
	if err != nil {
		t.Errorf("Échec d'arrêt de l'appel : %v", err)
	}

	if protocol.IsActive() {
		t.Error("Le protocole ne doit plus être actif après l'arrêt")
	}
}

func TestDoubleStartCall(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	// Premier démarrage
	err = protocol.StartSecureCall()
	if err != nil {
		t.Errorf("Premier démarrage échoué : %v", err)
	}

	// Deuxième démarrage (doit échouer)
	err = protocol.StartSecureCall()
	if err == nil {
		t.Error("Le double démarrage d'appel doit échouer")
	}

	protocol.StopSecureCall()
}

func TestSendAudioDataWithoutActiveCall(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	testData := []byte("test audio data")
	err = protocol.SendAudioData(testData)
	if err == nil {
		t.Error("L'envoi sans appel actif doit échouer")
	}
}

func TestSendReceiveAudioData(t *testing.T) {
	// Test avec un buffer partagé pour simuler la communication bidirectionnelle
	sharedBuffer := &bytes.Buffer{}

	// CORRECTION: Utiliser la même clé de session pour les deux protocoles
	senderConn := &MockConnectionWithSharedBuffer{Buffer: sharedBuffer, EnableLogging: false}
	receiverConn := &MockConnectionWithSharedBuffer{Buffer: sharedBuffer, EnableLogging: false}

	senderProtocol, err := communication.NewAudioProtocol(senderConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole expéditeur : %v", err)
	}

	receiverProtocol, err := communication.NewAudioProtocol(receiverConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole récepteur : %v", err)
	}

	// Démarrage des appels
	err = senderProtocol.StartSecureCall()
	if err != nil {
		t.Errorf("Échec de démarrage de l'appel expéditeur : %v", err)
	}

	err = receiverProtocol.StartSecureCall()
	if err != nil {
		t.Errorf("Échec de démarrage de l'appel récepteur : %v", err)
	}

	// Test d'envoi/réception de données audio
	testData := []byte("Hello, this is test audio data!")

	err = senderProtocol.SendAudioData(testData)
	if err != nil {
		t.Errorf("Échec d'envoi des données audio : %v", err)
	}

	// Note: Dans un vrai scénario, il faudrait une synchronisation plus complexe
	// Pour ce test simplifié, nous testons juste l'envoi

	// Nettoyage
	senderProtocol.StopSecureCall()
	receiverProtocol.StopSecureCall()
}

func TestSendOversizedAudioData(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	err = protocol.StartSecureCall()
	if err != nil {
		t.Errorf("Échec de démarrage de l'appel : %v", err)
	}

	// Création de données trop volumineuses (> 16KB)
	oversizedData := make([]byte, 1024*17) // 17KB

	err = protocol.SendAudioData(oversizedData)
	if err == nil {
		t.Error("L'envoi de données trop volumineuses doit échouer")
	}

	protocol.StopSecureCall()
}

func TestGetSessionInfo(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	info := protocol.GetSessionInfo()

	// Vérification des informations de session
	if info["is_active"] != false {
		t.Error("L'appel ne doit pas être actif initialement")
	}

	if info["session_key_size"].(int) != 32 {
		t.Error("La taille de la clé de session doit être de 32 bytes")
	}

	if info["nonce_size"].(int) != 12 {
		t.Error("La taille du nonce doit être de 12 bytes")
	}
}

func TestStopCallWithoutActiveCall(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	err = protocol.StopSecureCall()
	if err == nil {
		t.Error("L'arrêt sans appel actif doit échouer")
	}
}

func TestConcurrentAccess(t *testing.T) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		t.Fatalf("Échec de création du protocole : %v", err)
	}

	// Test d'accès concurrent sécurisé
	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 10; i++ {
			protocol.IsActive()
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 10; i++ {
			protocol.GetSessionInfo()
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Attendre la fin des goroutines
	<-done
	<-done
}

// MockConnectionWithSharedBuffer simule une connexion avec un buffer partagé
type MockConnectionWithSharedBuffer struct {
	Buffer        *bytes.Buffer
	EnableLogging bool
}

func (m *MockConnectionWithSharedBuffer) Read(b []byte) (n int, err error) {
	return m.Buffer.Read(b)
}

func (m *MockConnectionWithSharedBuffer) Write(b []byte) (n int, err error) {
	return m.Buffer.Write(b)
}

func (m *MockConnectionWithSharedBuffer) Close() error {
	return nil
}

// Benchmarks
func BenchmarkNewAudioProtocol(b *testing.B) {
	mockConn := &MockConnection{EnableLogging: false}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
		if err != nil {
			b.Fatalf("Échec de création du protocole : %v", err)
		}
		_ = protocol
	}
}

func BenchmarkSendAudioData(b *testing.B) {
	mockConn := &MockConnection{EnableLogging: false}
	protocol, err := communication.NewAudioProtocol(mockConn, sharedSessionKey)
	if err != nil {
		b.Fatalf("Échec de création du protocole : %v", err)
	}

	err = protocol.StartSecureCall()
	if err != nil {
		b.Fatalf("Échec de démarrage de l'appel : %v", err)
	}

	testData := []byte("benchmark test audio data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = protocol.SendAudioData(testData)
		if err != nil {
			b.Fatalf("Échec d'envoi des données : %v", err)
		}
	}

	protocol.StopSecureCall()
}
