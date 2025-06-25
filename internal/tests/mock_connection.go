package tests

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"
)

// Erreurs personnalisées pour remplacer les erreurs manquantes
var (
	ErrNotExist = errors.New("file does not exist")
)

// MockConnection simule une connexion bidirectionnelle pour les tests
type MockConnection struct {
	clientToServer *bytes.Buffer
	serverToClient *bytes.Buffer
	mu             sync.RWMutex
	closed         bool
}

// NewMockConnection crée une nouvelle connexion mock
func NewMockConnection() *MockConnection {
	return &MockConnection{
		clientToServer: &bytes.Buffer{},
		serverToClient: &bytes.Buffer{},
	}
}

// ClientSide retourne le côté client de la connexion
func (mc *MockConnection) ClientSide() *MockReadWriter {
	return &MockReadWriter{
		readBuffer:  mc.serverToClient,
		writeBuffer: mc.clientToServer,
		mu:          &mc.mu,
		connection:  mc,
		side:        "client",
	}
}

// ServerSide retourne le côté serveur de la connexion
func (mc *MockConnection) ServerSide() *MockReadWriter {
	return &MockReadWriter{
		readBuffer:  mc.clientToServer,
		writeBuffer: mc.serverToClient,
		mu:          &mc.mu,
		connection:  mc,
		side:        "server",
	}
}

// Close ferme la connexion
func (mc *MockConnection) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.closed = true
	return nil
}

// IsClosed vérifie si la connexion est fermée
func (mc *MockConnection) IsClosed() bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.closed
}

// MockReadWriter implémente io.ReadWriter pour un côté de la connexion
type MockReadWriter struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	mu          *sync.RWMutex
	connection  *MockConnection
	side        string
}

// Read lit des données depuis le buffer de lecture
func (mrw *MockReadWriter) Read(p []byte) (n int, err error) {
	mrw.mu.RLock()
	defer mrw.mu.RUnlock()

	if mrw.connection.closed {
		return 0, io.EOF
	}

	// Simuler un petit délai pour rendre plus réaliste
	time.Sleep(1 * time.Millisecond)

	return mrw.readBuffer.Read(p)
}

// Write écrit des données vers le buffer d'écriture
func (mrw *MockReadWriter) Write(p []byte) (n int, err error) {
	mrw.mu.Lock()
	defer mrw.mu.Unlock()

	if mrw.connection.closed {
		return 0, io.ErrClosedPipe
	}

	return mrw.writeBuffer.Write(p)
}

// Close ferme ce côté de la connexion
func (mrw *MockReadWriter) Close() error {
	return mrw.connection.Close()
}

// MockSessionManager gère les sessions de test
type MockSessionManager struct {
	sessions map[string]*MockSession
	mu       sync.RWMutex
}

// NewMockSessionManager crée un nouveau gestionnaire de sessions mock
func NewMockSessionManager() *MockSessionManager {
	return &MockSessionManager{
		sessions: make(map[string]*MockSession),
	}
}

// CreateSession crée une nouvelle session mock
func (msm *MockSessionManager) CreateSession(sessionID string) *MockSession {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	session := &MockSession{
		ID:       sessionID,
		Created:  time.Now(),
		Messages: make([]MockMessage, 0),
	}

	msm.sessions[sessionID] = session
	return session
}

// GetSession récupère une session existante
func (msm *MockSessionManager) GetSession(sessionID string) (*MockSession, bool) {
	msm.mu.RLock()
	defer msm.mu.RUnlock()

	session, exists := msm.sessions[sessionID]
	return session, exists
}

// DeleteSession supprime une session
func (msm *MockSessionManager) DeleteSession(sessionID string) {
	msm.mu.Lock()
	defer msm.mu.Unlock()

	delete(msm.sessions, sessionID)
}

// MockSession représente une session de test
type MockSession struct {
	ID       string
	Created  time.Time
	Messages []MockMessage
	mu       sync.RWMutex
}

// AddMessage ajoute un message à la session
func (ms *MockSession) AddMessage(content string, sequence uint64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	message := MockMessage{
		Content:   content,
		Sequence:  sequence,
		Timestamp: time.Now(),
	}

	ms.Messages = append(ms.Messages, message)
}

// GetMessages retourne tous les messages de la session
func (ms *MockSession) GetMessages() []MockMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	messages := make([]MockMessage, len(ms.Messages))
	copy(messages, ms.Messages)
	return messages
}

// MockMessage représente un message de test
type MockMessage struct {
	Content   string
	Sequence  uint64
	Timestamp time.Time
}

// MockBuffer est un buffer thread-safe pour les tests
type MockBuffer struct {
	buffer bytes.Buffer
	mu     sync.RWMutex
	closed bool
}

// NewMockBuffer crée un nouveau buffer mock
func NewMockBuffer() *MockBuffer {
	return &MockBuffer{}
}

// Read lit des données du buffer
func (mb *MockBuffer) Read(p []byte) (n int, err error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	if mb.closed {
		return 0, io.EOF
	}

	return mb.buffer.Read(p)
}

// Write écrit des données dans le buffer
func (mb *MockBuffer) Write(p []byte) (n int, err error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if mb.closed {
		return 0, io.ErrClosedPipe
	}

	return mb.buffer.Write(p)
}

// Close ferme le buffer
func (mb *MockBuffer) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.closed = true
	return nil
}

// Len retourne la taille du buffer
func (mb *MockBuffer) Len() int {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.buffer.Len()
}

// Reset vide le buffer
func (mb *MockBuffer) Reset() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.buffer.Reset()
}

// String retourne le contenu du buffer en tant que string
func (mb *MockBuffer) String() string {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.buffer.String()
}

// MockFileSystem simule un système de fichiers pour les tests
type MockFileSystem struct {
	files map[string][]byte
	mu    sync.RWMutex
}

// NewMockFileSystem crée un nouveau système de fichiers mock
func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		files: make(map[string][]byte),
	}
}

// WriteFile simule l'écriture d'un fichier
func (mfs *MockFileSystem) WriteFile(filename string, data []byte) error {
	mfs.mu.Lock()
	defer mfs.mu.Unlock()

	mfs.files[filename] = make([]byte, len(data))
	copy(mfs.files[filename], data)
	return nil
}

// ReadFile simule la lecture d'un fichier
func (mfs *MockFileSystem) ReadFile(filename string) ([]byte, error) {
	mfs.mu.RLock()
	defer mfs.mu.RUnlock()

	data, exists := mfs.files[filename]
	if !exists {
		return nil, ErrNotExist
	}

	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// FileExists vérifie si un fichier existe
func (mfs *MockFileSystem) FileExists(filename string) bool {
	mfs.mu.RLock()
	defer mfs.mu.RUnlock()

	_, exists := mfs.files[filename]
	return exists
}

// DeleteFile supprime un fichier
func (mfs *MockFileSystem) DeleteFile(filename string) error {
	mfs.mu.Lock()
	defer mfs.mu.Unlock()

	delete(mfs.files, filename)
	return nil
}

// ListFiles retourne la liste des fichiers
func (mfs *MockFileSystem) ListFiles() []string {
	mfs.mu.RLock()
	defer mfs.mu.RUnlock()

	files := make([]string, 0, len(mfs.files))
	for filename := range mfs.files {
		files = append(files, filename)
	}
	return files
}

// MockNetworkSimulator simule des conditions réseau
type MockNetworkSimulator struct {
	latency    time.Duration
	packetLoss float64
	bandwidth  int // bytes per second
	mu         sync.RWMutex
}

// NewMockNetworkSimulator crée un nouveau simulateur réseau
func NewMockNetworkSimulator() *MockNetworkSimulator {
	return &MockNetworkSimulator{
		latency:    0,
		packetLoss: 0,
		bandwidth:  0, // 0 = illimité
	}
}

// SetLatency configure la latence
func (mns *MockNetworkSimulator) SetLatency(latency time.Duration) {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	mns.latency = latency
}

// SetPacketLoss configure le taux de perte de paquets (0.0 à 1.0)
func (mns *MockNetworkSimulator) SetPacketLoss(loss float64) {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	mns.packetLoss = loss
}

// SetBandwidth configure la bande passante (0 = illimitée)
func (mns *MockNetworkSimulator) SetBandwidth(bandwidth int) {
	mns.mu.Lock()
	defer mns.mu.Unlock()
	mns.bandwidth = bandwidth
}

// SimulateTransmission simule la transmission de données
func (mns *MockNetworkSimulator) SimulateTransmission(data []byte) error {
	mns.mu.RLock()
	latency := mns.latency
	packetLoss := mns.packetLoss
	bandwidth := mns.bandwidth
	mns.mu.RUnlock()

	// Simuler la perte de paquets
	if packetLoss > 0 && packetLoss >= 1.0 {
		return io.ErrUnexpectedEOF
	}

	// Simuler la latence
	if latency > 0 {
		time.Sleep(latency)
	}

	// Simuler la limitation de bande passante
	if bandwidth > 0 {
		transmissionTime := time.Duration(len(data)) * time.Second / time.Duration(bandwidth)
		time.Sleep(transmissionTime)
	}

	return nil
}

// MockCrypto fournit des fonctions cryptographiques simplifiées pour les tests
type MockCrypto struct{}

// NewMockCrypto crée une nouvelle instance de crypto mock
func NewMockCrypto() *MockCrypto {
	return &MockCrypto{}
}

// GenerateRandomBytes génère des bytes aléatoires mock
func (mc *MockCrypto) GenerateRandomBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

// MockEncrypt simule le chiffrement
func (mc *MockCrypto) MockEncrypt(data []byte, key []byte) []byte {
	// Chiffrement XOR simple pour les tests
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ key[i%len(key)]
	}
	return encrypted
}

// MockDecrypt simule le déchiffrement
func (mc *MockCrypto) MockDecrypt(encrypted []byte, key []byte) []byte {
	// Déchiffrement XOR simple pour les tests
	decrypted := make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ key[i%len(key)]
	}
	return decrypted
}

// MockKeyExchanger simule un échange de clés
type MockKeyExchanger struct {
	sharedSecret []byte
}

// NewMockKeyExchanger crée un nouvel échangeur de clés mock
func NewMockKeyExchanger() *MockKeyExchanger {
	return &MockKeyExchanger{
		sharedSecret: []byte("mock-shared-secret-32-bytes-long"),
	}
}

// PerformExchange simule un échange de clés
func (mke *MockKeyExchanger) PerformExchange() ([]byte, error) {
	// Retourner un secret partagé prédéterminé
	result := make([]byte, len(mke.sharedSecret))
	copy(result, mke.sharedSecret)
	return result, nil
}

// SetSharedSecret configure le secret partagé
func (mke *MockKeyExchanger) SetSharedSecret(secret []byte) {
	mke.sharedSecret = make([]byte, len(secret))
	copy(mke.sharedSecret, secret)
}
