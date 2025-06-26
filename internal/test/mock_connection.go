package test

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"
)

// MockConnection simule une connexion réseau pour les tests
type MockConnection struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	mu          sync.RWMutex
	closed      bool
	readDelay   time.Duration
	writeDelay  time.Duration
	readError   error
	writeError  error
	maxReadSize int
}

// NewMockConnection crée une nouvelle connexion mock
func NewMockConnection() *MockConnection {
	return &MockConnection{
		readBuffer:  bytes.NewBuffer(nil),
		writeBuffer: bytes.NewBuffer(nil),
		maxReadSize: 64 * 1024, // 64KB par défaut
	}
}

// NewMockConnectionPair crée une paire de connexions connectées - AMÉLIORÉ
func NewMockConnectionPair() (*MockConnection, *MockConnection) {
	// Créer des buffers partagés pour la communication bidirectionnelle
	buffer1to2 := bytes.NewBuffer(nil)
	buffer2to1 := bytes.NewBuffer(nil)

	conn1 := &MockConnection{
		readBuffer:  buffer2to1, // conn1 lit ce que conn2 écrit
		writeBuffer: buffer1to2, // conn1 écrit vers conn2
		maxReadSize: 64 * 1024,
	}

	conn2 := &MockConnection{
		readBuffer:  buffer1to2, // conn2 lit ce que conn1 écrit
		writeBuffer: buffer2to1, // conn2 écrit vers conn1
		maxReadSize: 64 * 1024,
	}

	return conn1, conn2
}

// Read implémente io.Reader avec meilleure gestion des erreurs
func (mc *MockConnection) Read(p []byte) (n int, err error) {
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, io.EOF
	}
	if mc.readError != nil {
		mc.mu.RUnlock()
		return 0, mc.readError
	}
	if mc.readDelay > 0 {
		mc.mu.RUnlock()
		time.Sleep(mc.readDelay)
		mc.mu.RLock()
	}
	mc.mu.RUnlock()

	// Attente active de données (max 500 ms)
	if !mc.WaitForData(500 * time.Millisecond) {
		return 0, io.EOF
	}

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Limiter la taille de lecture si configuré
	if mc.maxReadSize > 0 && len(p) > mc.maxReadSize {
		p = p[:mc.maxReadSize]
	}

	return mc.readBuffer.Read(p)
}

// Write implémente io.Writer
func (mc *MockConnection) Write(p []byte) (n int, err error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return 0, errors.New("connection closed")
	}

	if mc.writeError != nil {
		return 0, mc.writeError
	}

	if mc.writeDelay > 0 {
		time.Sleep(mc.writeDelay)
	}

	return mc.writeBuffer.Write(p)
}

// Close implémente io.Closer
func (mc *MockConnection) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.closed = true
	return nil
}

// WriteToReadBuffer écrit directement dans le buffer de lecture (pour simulation)
func (mc *MockConnection) WriteToReadBuffer(data []byte) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.readBuffer.Write(data)
}

// ReadFromWriteBuffer lit directement depuis le buffer d'écriture
func (mc *MockConnection) ReadFromWriteBuffer() []byte {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.writeBuffer.Bytes()
}

// ClearBuffers vide tous les buffers
func (mc *MockConnection) ClearBuffers() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.readBuffer.Reset()
	mc.writeBuffer.Reset()
}

// SetReadError configure une erreur de lecture
func (mc *MockConnection) SetReadError(err error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.readError = err
}

// SetWriteError configure une erreur d'écriture
func (mc *MockConnection) SetWriteError(err error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.writeError = err
}

// SetReadDelay configure un délai de lecture
func (mc *MockConnection) SetReadDelay(delay time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.readDelay = delay
}

// SetWriteDelay configure un délai d'écriture
func (mc *MockConnection) SetWriteDelay(delay time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.writeDelay = delay
}

// SetMaxReadSize configure la taille maximale de lecture
func (mc *MockConnection) SetMaxReadSize(size int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.maxReadSize = size
}

// IsClosed retourne l'état de la connexion
func (mc *MockConnection) IsClosed() bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.closed
}

// GetReadBufferSize retourne la taille du buffer de lecture
func (mc *MockConnection) GetReadBufferSize() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.readBuffer.Len()
}

// GetWriteBufferSize retourne la taille du buffer d'écriture
func (mc *MockConnection) GetWriteBufferSize() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.writeBuffer.Len()
}

// SimulateNetworkPartition simule une partition réseau
func (mc *MockConnection) SimulateNetworkPartition() {
	mc.SetReadError(errors.New("network partition"))
	mc.SetWriteError(errors.New("network partition"))
}

// RestoreConnection restaure la connexion après une partition
func (mc *MockConnection) RestoreConnection() {
	mc.SetReadError(nil)
	mc.SetWriteError(nil)
}

// SimulateSlowNetwork simule un réseau lent
func (mc *MockConnection) SimulateSlowNetwork(delay time.Duration) {
	mc.SetReadDelay(delay)
	mc.SetWriteDelay(delay)
}

// SimulateLimitedBandwidth simule une bande passante limitée
func (mc *MockConnection) SimulateLimitedBandwidth(maxSize int) {
	mc.SetMaxReadSize(maxSize)
}

// WaitForData attend que des données soient disponibles dans le buffer de lecture - AMÉLIORÉ
func (mc *MockConnection) WaitForData(timeout time.Duration) bool {
	start := time.Now()
	for time.Since(start) < timeout {
		if mc.GetReadBufferSize() > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond) // Vérification plus fréquente
	}
	return false
}

// WaitForWrite attend qu'une écriture soit effectuée - AMÉLIORÉ
func (mc *MockConnection) WaitForWrite(timeout time.Duration) bool {
	start := time.Now()
	initialSize := mc.GetWriteBufferSize()

	for time.Since(start) < timeout {
		if mc.GetWriteBufferSize() > initialSize {
			return true
		}
		time.Sleep(5 * time.Millisecond) // Vérification plus fréquente
	}
	return false
}

// FlushBuffers force l'écriture des buffers (simulation)
func (mc *MockConnection) FlushBuffers() {
	// Rien à faire pour les buffers en mémoire, mais utile pour l'interface
}

// MockConnectionStats retourne des statistiques sur la connexion mock
type MockConnectionStats struct {
	ReadBufferSize  int
	WriteBufferSize int
	IsClosed        bool
	ReadDelay       time.Duration
	WriteDelay      time.Duration
	HasReadError    bool
	HasWriteError   bool
}

// GetStats retourne les statistiques de la connexion
func (mc *MockConnection) GetStats() MockConnectionStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return MockConnectionStats{
		ReadBufferSize:  mc.readBuffer.Len(),
		WriteBufferSize: mc.writeBuffer.Len(),
		IsClosed:        mc.closed,
		ReadDelay:       mc.readDelay,
		WriteDelay:      mc.writeDelay,
		HasReadError:    mc.readError != nil,
		HasWriteError:   mc.writeError != nil,
	}
}
