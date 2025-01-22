package tests

import (
	"bytes"
	"log"
	"net"
	"time"
)

// MockConnection est une structure simulant une connexion réseau pour les tests.
type MockConnection struct {
	Buffer        bytes.Buffer
	Remote        net.Addr
	EnableLogging bool // Ajout d'un flag pour activer/désactiver les logs
}

func (m *MockConnection) Read(b []byte) (n int, err error) {
	return m.Buffer.Read(b)
}

func (m *MockConnection) Write(b []byte) (n int, err error) {
	// Log de l'envoi dans le buffer seulement si EnableLogging est activé
	if m.EnableLogging {
		log.Printf("Message écrit dans le buffer: %s", string(b))
	}
	return m.Buffer.Write(b)
}

func (m *MockConnection) Close() error {
	return nil
}

func (m *MockConnection) RemoteAddr() net.Addr {
	if m.Remote == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	}
	return m.Remote
}

func (m *MockConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
}

func (m *MockConnection) SetDeadline(t time.Time) error      { return nil }
func (m *MockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConnection) SetWriteDeadline(t time.Time) error { return nil }
