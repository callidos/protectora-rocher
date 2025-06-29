package rocher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	channelKeySize    = 32
	channelNonceSize  = 24
	maxChannelMessage = 65535
	channelOverhead   = secretbox.Overhead
)

var (
	ErrChannelNotInitialized = errors.New("secure channel not initialized")
	ErrChannelClosed         = errors.New("secure channel closed")
	ErrInvalidNonce          = errors.New("invalid nonce sequence")
	ErrMessageTooLarge       = errors.New("message too large for secure channel")
)

// SecureChannel gère une communication chiffrée bidirectionnelle avec NaCl secretbox
type SecureChannel struct {
	// Clés de chiffrement séparées pour chaque direction
	sendKey [channelKeySize]byte
	recvKey [channelKeySize]byte

	// Nonces séquentiels pour éviter la réutilisation
	sendNonce uint64
	recvNonce uint64

	// Connexion sous-jacente
	conn io.ReadWriter

	// État et protection concurrentielle
	isInitialized bool
	isClosed      bool
	mu            sync.RWMutex

	// Métadonnées
	isClient   bool
	sessionID  string
	startTime  time.Time
	lastActive time.Time

	// Compteurs de messages
	messagesSent     uint64
	messagesReceived uint64
	bytesSent        uint64
	bytesReceived    uint64
}

// NewSecureChannel crée un nouveau canal sécurisé à partir d'un secret partagé
func NewSecureChannel(conn io.ReadWriter, sharedSecret [32]byte, isClient bool) (*SecureChannel, error) {
	if conn == nil {
		return nil, errors.New("connection cannot be nil")
	}

	// Générer un ID de session unique
	sessionID := generateSessionID()

	sc := &SecureChannel{
		conn:          conn,
		isClient:      isClient,
		sessionID:     sessionID,
		startTime:     time.Now(),
		lastActive:    time.Now(),
		isInitialized: false,
		isClosed:      false,
	}

	// Dériver des clés séparées pour l'envoi et la réception
	if err := sc.deriveChannelKeys(sharedSecret); err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	sc.isInitialized = true
	return sc, nil
}

// deriveChannelKeys dérive les clés d'envoi et de réception séparées
func (sc *SecureChannel) deriveChannelKeys(sharedSecret [32]byte) error {
	salt := []byte("protectora-rocher-channel-salt-v2")

	// Dériver clés différentes selon le rôle (client/serveur)
	var sendInfo, recvInfo []byte
	if sc.isClient {
		sendInfo = []byte("protectora-rocher-client-send-v2")
		recvInfo = []byte("protectora-rocher-client-recv-v2")
	} else {
		sendInfo = []byte("protectora-rocher-server-send-v2")
		recvInfo = []byte("protectora-rocher-server-recv-v2")
	}

	// Dérivation clé d'envoi
	hkdfSend := hkdf.New(sha256.New, sharedSecret[:], salt, sendInfo)
	if _, err := io.ReadFull(hkdfSend, sc.sendKey[:]); err != nil {
		return fmt.Errorf("send key derivation failed: %w", err)
	}

	// Dérivation clé de réception
	hkdfRecv := hkdf.New(sha256.New, sharedSecret[:], salt, recvInfo)
	if _, err := io.ReadFull(hkdfRecv, sc.recvKey[:]); err != nil {
		return fmt.Errorf("recv key derivation failed: %w", err)
	}

	// Vérifier que les clés ne sont pas nulles
	if isAllZeros(sc.sendKey[:]) || isAllZeros(sc.recvKey[:]) {
		return errors.New("derived keys are zero")
	}

	return nil
}

// SendMessage chiffre et envoie un message de manière thread-safe
func (sc *SecureChannel) SendMessage(plaintext []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized {
		return ErrChannelNotInitialized
	}

	if sc.isClosed {
		return ErrChannelClosed
	}

	if len(plaintext) > maxChannelMessage {
		return ErrMessageTooLarge
	}

	// Préparer le nonce avec le compteur séquentiel
	var nonce [channelNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], sc.sendNonce)

	// Ajouter de l'entropie supplémentaire dans le nonce
	if _, err := rand.Read(nonce[8:16]); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Chiffrer avec NaCl secretbox
	ciphertext := secretbox.Seal(nil, plaintext, &nonce, &sc.sendKey)

	// Format du message: nonce (24 bytes) + ciphertext
	message := make([]byte, channelNonceSize+len(ciphertext))
	copy(message[:channelNonceSize], nonce[:])
	copy(message[channelNonceSize:], ciphertext)

	// Envoyer le message
	if err := sc.sendRawMessage(message); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	// Mettre à jour les statistiques
	sc.sendNonce++
	sc.messagesSent++
	sc.bytesSent += uint64(len(plaintext))
	sc.lastActive = time.Now()

	return nil
}

// ReceiveMessage reçoit et déchiffre un message de manière thread-safe
func (sc *SecureChannel) ReceiveMessage() ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized {
		return nil, ErrChannelNotInitialized
	}

	if sc.isClosed {
		return nil, ErrChannelClosed
	}

	// Recevoir le message brut
	message, err := sc.receiveRawMessage()
	if err != nil {
		return nil, fmt.Errorf("receive failed: %w", err)
	}

	// Vérifier la taille minimale
	if len(message) < channelNonceSize+channelOverhead {
		return nil, ErrInvalidMessage
	}

	// Extraire le nonce et le ciphertext
	var nonce [channelNonceSize]byte
	copy(nonce[:], message[:channelNonceSize])
	ciphertext := message[channelNonceSize:]

	// Vérifier la séquence des nonces
	receivedSeq := binary.LittleEndian.Uint64(nonce[:8])
	if receivedSeq != sc.recvNonce {
		return nil, ErrInvalidNonce
	}

	// Déchiffrer avec NaCl secretbox
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &sc.recvKey)
	if !ok {
		return nil, ErrInvalidMessage
	}

	// Mettre à jour les statistiques
	sc.recvNonce++
	sc.messagesReceived++
	sc.bytesReceived += uint64(len(plaintext))
	sc.lastActive = time.Now()

	return plaintext, nil
}

// SendMessageWithTimeout envoie un message avec timeout
func (sc *SecureChannel) SendMessageWithTimeout(plaintext []byte, timeout time.Duration) error {
	if timeout <= 0 {
		return sc.SendMessage(plaintext)
	}

	done := make(chan error, 1)
	go func() {
		done <- sc.SendMessage(plaintext)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return NewTimeoutError("Send message timeout", nil)
	}
}

// ReceiveMessageWithTimeout reçoit un message avec timeout
func (sc *SecureChannel) ReceiveMessageWithTimeout(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		return sc.ReceiveMessage()
	}

	type result struct {
		data []byte
		err  error
	}

	done := make(chan result, 1)
	go func() {
		data, err := sc.ReceiveMessage()
		done <- result{data: data, err: err}
	}()

	select {
	case res := <-done:
		return res.data, res.err
	case <-time.After(timeout):
		return nil, NewTimeoutError("Receive message timeout", nil)
	}
}

// sendRawMessage envoie un message brut avec préfixe de longueur
func (sc *SecureChannel) sendRawMessage(data []byte) error {
	// Format: longueur (4 bytes) + données
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))

	// Envoyer longueur puis données
	if _, err := sc.conn.Write(lengthBytes); err != nil {
		return err
	}

	totalWritten := 0
	for totalWritten < len(data) {
		n, err := sc.conn.Write(data[totalWritten:])
		if err != nil {
			return err
		}
		totalWritten += n
	}

	return nil
}

// receiveRawMessage reçoit un message brut avec préfixe de longueur
func (sc *SecureChannel) receiveRawMessage() ([]byte, error) {
	// Lire la longueur
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(sc.conn, lengthBytes); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lengthBytes)

	// Valider la longueur
	if length == 0 {
		return nil, ErrInvalidMessage
	}
	if length > maxChannelMessage+channelNonceSize+channelOverhead {
		return nil, ErrMessageTooLarge
	}

	// Lire les données
	data := make([]byte, length)
	if _, err := io.ReadFull(sc.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// Close ferme le canal sécurisé et nettoie les ressources
func (sc *SecureChannel) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.isClosed {
		return nil
	}

	// Nettoyer les clés de manière sécurisée
	secureZeroMemory(sc.sendKey[:])
	secureZeroMemory(sc.recvKey[:])

	sc.isClosed = true
	sc.isInitialized = false

	// Fermer la connexion si possible
	if closer, ok := sc.conn.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

// IsActive retourne l'état du canal
func (sc *SecureChannel) IsActive() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.isInitialized && !sc.isClosed
}

// IsIdle vérifie si le canal est inactif depuis un certain temps
func (sc *SecureChannel) IsIdle(maxIdleTime time.Duration) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return time.Since(sc.lastActive) > maxIdleTime
}

// GetSessionID retourne l'identifiant de session
func (sc *SecureChannel) GetSessionID() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.sessionID
}

// GetStats retourne les statistiques du canal
func (sc *SecureChannel) GetStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return map[string]interface{}{
		"session_id":        sc.sessionID,
		"is_client":         sc.isClient,
		"is_active":         sc.isInitialized && !sc.isClosed,
		"start_time":        sc.startTime,
		"last_active":       sc.lastActive,
		"duration":          time.Since(sc.startTime),
		"idle_time":         time.Since(sc.lastActive),
		"messages_sent":     sc.messagesSent,
		"messages_received": sc.messagesReceived,
		"bytes_sent":        sc.bytesSent,
		"bytes_received":    sc.bytesReceived,
		"send_nonce":        sc.sendNonce,
		"recv_nonce":        sc.recvNonce,
		"cipher":            "NaCl-secretbox",
		"max_message_size":  maxChannelMessage,
	}
}

// RekeyChannel effectue un re-keying du canal (pour une sécurité renforcée)
func (sc *SecureChannel) RekeyChannel(newSharedSecret [32]byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.isInitialized || sc.isClosed {
		return ErrChannelNotInitialized
	}

	// Nettoyer les anciennes clés
	secureZeroMemory(sc.sendKey[:])
	secureZeroMemory(sc.recvKey[:])

	// Dériver de nouvelles clés
	if err := sc.deriveChannelKeys(newSharedSecret); err != nil {
		return fmt.Errorf("rekey failed: %w", err)
	}

	// Réinitialiser les nonces
	sc.sendNonce = 0
	sc.recvNonce = 0
	sc.lastActive = time.Now()

	return nil
}

// generateSessionID génère un identifiant de session unique
func generateSessionID() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback en cas d'erreur
		return fmt.Sprintf("channel_%d", time.Now().UnixNano())
	}

	return fmt.Sprintf("channel_%x", randomBytes)
}

// EstimateChannelOverhead estime l'overhead du canal sécurisé
func EstimateChannelOverhead() map[string]int {
	return map[string]int{
		"nonce_size":         channelNonceSize,
		"secretbox_overhead": channelOverhead,
		"length_prefix":      4,
		"per_message_total":  channelNonceSize + channelOverhead + 4,
		"max_message_size":   maxChannelMessage,
		"key_size":           channelKeySize,
	}
}

// CreateSecureChannelPair crée une paire de canaux sécurisés connectés (pour tests)
func CreateSecureChannelPair(sharedSecret [32]byte) (*SecureChannel, *SecureChannel, error) {
	// Créer une paire de pipes connectées
	clientConn, serverConn := createConnectedPair()

	// Créer les canaux
	clientChannel, err := NewSecureChannel(clientConn, sharedSecret, true)
	if err != nil {
		return nil, nil, fmt.Errorf("client channel creation failed: %w", err)
	}

	serverChannel, err := NewSecureChannel(serverConn, sharedSecret, false)
	if err != nil {
		clientChannel.Close()
		return nil, nil, fmt.Errorf("server channel creation failed: %w", err)
	}

	return clientChannel, serverChannel, nil
}

// connectedPair implémente une paire de connexions connectées pour les tests
type connectedPair struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func (cp *connectedPair) Read(p []byte) (n int, err error) {
	return cp.reader.Read(p)
}

func (cp *connectedPair) Write(p []byte) (n int, err error) {
	return cp.writer.Write(p)
}

func (cp *connectedPair) Close() error {
	cp.reader.Close()
	return cp.writer.Close()
}

// createConnectedPair crée une paire de connexions bidirectionnelles
func createConnectedPair() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	conn1 := &connectedPair{reader: r1, writer: w2}
	conn2 := &connectedPair{reader: r2, writer: w1}

	return conn1, conn2
}

// ValidateSecureChannel valide l'état d'un canal sécurisé
func ValidateSecureChannel(sc *SecureChannel) error {
	if sc == nil {
		return errors.New("secure channel is nil")
	}

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if !sc.isInitialized {
		return ErrChannelNotInitialized
	}

	if sc.isClosed {
		return ErrChannelClosed
	}

	if sc.conn == nil {
		return errors.New("connection is nil")
	}

	if isAllZeros(sc.sendKey[:]) || isAllZeros(sc.recvKey[:]) {
		return errors.New("encryption keys are zero")
	}

	return nil
}
