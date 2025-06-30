// messenger.go
package rocher

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrNotConnected     = errors.New("not connected")
	ErrAlreadyConnected = errors.New("already connected")
	ErrConnectionFailed = errors.New("connection failed")
	ErrReconnecting     = errors.New("reconnection in progress")
)

// CompressionType définit les algorithmes de compression supportés
type CompressionType int

const (
	NoCompression CompressionType = iota
	GzipCompression
)

// ReconnectPolicy configure la politique de reconnexion
type ReconnectPolicy struct {
	MaxAttempts  int           // Nombre max de tentatives (-1 = infini)
	InitialDelay time.Duration // Délai initial
	MaxDelay     time.Duration // Délai maximum
	Multiplier   float64       // Facteur d'augmentation du délai
	Enabled      bool          // Activer la reconnexion auto
}

// DefaultReconnectPolicy retourne une politique par défaut
func DefaultReconnectPolicy() *ReconnectPolicy {
	return &ReconnectPolicy{
		MaxAttempts:  5,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Enabled:      true,
	}
}

// KeepAliveConfig configure le heartbeat
type KeepAliveConfig struct {
	Interval  time.Duration // Intervalle entre les pings
	Timeout   time.Duration // Timeout pour la réponse
	MaxMissed int           // Nombre max de pings ratés
	Enabled   bool          // Activer le keep-alive
}

// DefaultKeepAliveConfig retourne une configuration par défaut
func DefaultKeepAliveConfig() *KeepAliveConfig {
	return &KeepAliveConfig{
		Interval:  30 * time.Second,
		Timeout:   10 * time.Second,
		MaxMissed: 3,
		Enabled:   true,
	}
}

// CompressionConfig configure la compression
type CompressionConfig struct {
	Type      CompressionType // Algorithme de compression
	Threshold int             // Taille min pour compresser (bytes)
	Level     int             // Niveau de compression (1-9 pour gzip)
	Enabled   bool            // Activer la compression
}

// DefaultCompressionConfig retourne une configuration par défaut
func DefaultCompressionConfig() *CompressionConfig {
	return &CompressionConfig{
		Type:      GzipCompression,
		Threshold: 1024, // Compresser si > 1KB
		Level:     6,    // Compression moyenne
		Enabled:   true,
	}
}

// ConnectorFunc type pour la fonction de connexion
type ConnectorFunc func() (io.ReadWriter, error)

// SimpleMessenger combine l'échange de clés Kyber et le chiffrement NaCl avec fonctionnalités avancées
type SimpleMessenger struct {
	// Composants de base
	keyExchange *KyberKeyExchange
	channel     *SecureChannelWithFS // Utilise SecureChannelWithFS

	// État
	isInitiator bool
	isConnected bool
	startTime   time.Time

	// Connexion
	connector ConnectorFunc // Fonction pour se reconnecter
	conn      io.ReadWriter

	// Configurations
	reconnectPolicy   *ReconnectPolicy
	keepAliveConfig   *KeepAliveConfig
	compressionConfig *CompressionConfig
	keyRotationConfig *KeyRotationConfig

	// État de reconnexion
	isReconnecting  bool
	reconnectCount  int
	lastConnectTime time.Time

	// Keep-alive
	lastPing    time.Time
	lastPong    time.Time
	missedPings int
	pingTicker  *time.Ticker
	stopPing    chan struct{}

	// Statistiques
	messagesSent      uint64
	messagesReceived  uint64
	bytesSent         uint64
	bytesReceived     uint64
	reconnectAttempts uint64
	compressionSaved  uint64

	// Thread safety
	mu sync.RWMutex

	// Contrôle des goroutines
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewSimpleMessenger crée un nouveau messenger avec configurations par défaut
func NewSimpleMessenger(isInitiator bool) *SimpleMessenger {
	return &SimpleMessenger{
		keyExchange:       NewKyberKeyExchange(),
		isInitiator:       isInitiator,
		startTime:         time.Now(),
		reconnectPolicy:   DefaultReconnectPolicy(),
		keepAliveConfig:   DefaultKeepAliveConfig(),
		compressionConfig: DefaultCompressionConfig(),
		keyRotationConfig: DefaultKeyRotationConfig(),
		stopChan:          make(chan struct{}),
		stopPing:          make(chan struct{}),
	}
}

// SetReconnectPolicy configure la politique de reconnexion
func (sm *SimpleMessenger) SetReconnectPolicy(policy *ReconnectPolicy) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.reconnectPolicy = policy
}

// SetKeepAliveConfig configure le heartbeat
func (sm *SimpleMessenger) SetKeepAliveConfig(config *KeepAliveConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.keepAliveConfig = config
}

// SetCompressionConfig configure la compression
func (sm *SimpleMessenger) SetCompressionConfig(config *CompressionConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.compressionConfig = config
}

// SetKeyRotationConfig configure la rotation des clés
func (sm *SimpleMessenger) SetKeyRotationConfig(config *KeyRotationConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.keyRotationConfig = config

	// Appliquer la config au canal existant si connecté
	if sm.channel != nil {
		sm.channel.SetKeyRotationConfig(config)
	}
}

// Connect établit une connexion sécurisée avec échange de clés Kyber
func (sm *SimpleMessenger) Connect(conn io.ReadWriter) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.isConnected {
		return ErrAlreadyConnected
	}

	if sm.isReconnecting {
		return ErrReconnecting
	}

	return sm.connectInternal(conn)
}

// ConnectWithReconnect établit une connexion avec support de reconnexion automatique
func (sm *SimpleMessenger) ConnectWithReconnect(connector ConnectorFunc) error {
	sm.mu.Lock()
	sm.connector = connector
	sm.mu.Unlock()

	// Première connexion
	conn, err := connector()
	if err != nil {
		return fmt.Errorf("initial connection failed: %w", err)
	}

	if err := sm.Connect(conn); err != nil {
		return err
	}

	// Démarrer les services
	sm.startServices()

	return nil
}

// connectInternal effectue la connexion sans verrouillage (appelé avec mutex acquis)
func (sm *SimpleMessenger) connectInternal(conn io.ReadWriter) error {
	sm.conn = conn
	sm.lastConnectTime = time.Now()

	// Effectuer l'échange de clés Kyber768
	sharedSecret, err := sm.keyExchange.PerformKeyExchange(conn, sm.isInitiator)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	// Créer le canal sécurisé avec Forward Secrecy
	sm.channel, err = NewSecureChannelWithFS(sharedSecret, sm.isInitiator)
	if err != nil {
		// Nettoyer le secret en cas d'erreur
		secureZeroMemory(sharedSecret)
		return fmt.Errorf("secure channel creation failed: %w", err)
	}

	// Appliquer la configuration de rotation des clés
	sm.channel.SetKeyRotationConfig(sm.keyRotationConfig)

	// Définir le callback de rotation
	sm.channel.SetOnKeyRotation(func(rotationID uint64) error {
		// Log ou autres actions lors de la rotation
		if sm.keyRotationConfig.Enabled {
			// Optionnel: notifier l'application de la rotation
		}
		return nil
	})

	// Nettoyer le secret de la mémoire
	secureZeroMemory(sharedSecret)

	sm.isConnected = true
	sm.isReconnecting = false
	sm.reconnectCount = 0

	return nil
}

// startServices démarre les services (keep-alive, etc.)
func (sm *SimpleMessenger) startServices() {
	if sm.keepAliveConfig.Enabled {
		sm.startKeepAlive()
	}
}

// startKeepAlive démarre le service de heartbeat
func (sm *SimpleMessenger) startKeepAlive() {
	sm.mu.Lock()
	if sm.pingTicker != nil {
		sm.pingTicker.Stop()
	}
	sm.pingTicker = time.NewTicker(sm.keepAliveConfig.Interval)
	sm.mu.Unlock()

	sm.wg.Add(1)
	go sm.keepAliveLoop()
}

// keepAliveLoop boucle principale du keep-alive
func (sm *SimpleMessenger) keepAliveLoop() {
	defer sm.wg.Done()

	for {
		select {
		case <-sm.stopChan:
			return
		case <-sm.stopPing:
			return
		case <-sm.pingTicker.C:
			if err := sm.sendPing(); err != nil {
				sm.handleKeepAliveFailure()
			}
		}
	}
}

// sendPing envoie un message de ping
func (sm *SimpleMessenger) sendPing() error {
	sm.mu.Lock()
	if !sm.isConnected {
		sm.mu.Unlock()
		return ErrNotConnected
	}
	conn := sm.conn
	sm.mu.Unlock()

	pingMsg := fmt.Sprintf("PING:%d", time.Now().UnixNano())
	err := sm.SendMessage(pingMsg, "ping", "system", "ping-session", conn.(io.Writer))
	if err == nil {
		sm.mu.Lock()
		sm.lastPing = time.Now()
		sm.mu.Unlock()
	}

	return err
}

// handleKeepAliveFailure gère les échecs de keep-alive
func (sm *SimpleMessenger) handleKeepAliveFailure() {
	sm.mu.Lock()
	sm.missedPings++
	maxMissed := sm.keepAliveConfig.MaxMissed
	sm.mu.Unlock()

	if sm.missedPings >= maxMissed {
		sm.triggerReconnect()
	}
}

// triggerReconnect déclenche une reconnexion
func (sm *SimpleMessenger) triggerReconnect() {
	sm.mu.Lock()
	if sm.isReconnecting || !sm.reconnectPolicy.Enabled || sm.connector == nil {
		sm.mu.Unlock()
		return
	}

	sm.isReconnecting = true
	sm.isConnected = false
	sm.mu.Unlock()

	sm.wg.Add(1)
	go sm.reconnectLoop()
}

// reconnectLoop boucle de reconnexion avec backoff exponentiel
func (sm *SimpleMessenger) reconnectLoop() {
	defer sm.wg.Done()

	delay := sm.reconnectPolicy.InitialDelay

	for attempt := 1; attempt <= sm.reconnectPolicy.MaxAttempts || sm.reconnectPolicy.MaxAttempts == -1; attempt++ {
		select {
		case <-sm.stopChan:
			return
		case <-time.After(delay):
			// Tentative de reconnexion
			conn, err := sm.connector()
			if err == nil {
				sm.mu.Lock()
				err = sm.connectInternal(conn)
				sm.mu.Unlock()

				if err == nil {
					sm.mu.Lock()
					sm.reconnectAttempts++
					sm.missedPings = 0
					sm.mu.Unlock()

					sm.startServices()
					return // Reconnexion réussie
				}
			}

			// Augmenter le délai avec backoff exponentiel
			delay = time.Duration(float64(delay) * sm.reconnectPolicy.Multiplier)
			if delay > sm.reconnectPolicy.MaxDelay {
				delay = sm.reconnectPolicy.MaxDelay
			}

			sm.mu.Lock()
			sm.reconnectCount++
			sm.mu.Unlock()
		}
	}

	// Échec de toutes les tentatives
	sm.mu.Lock()
	sm.isReconnecting = false
	sm.mu.Unlock()
}

// compressMessage compresse un message si nécessaire
func (sm *SimpleMessenger) compressMessage(data []byte) ([]byte, bool, error) {
	if !sm.compressionConfig.Enabled || len(data) < sm.compressionConfig.Threshold {
		return data, false, nil
	}

	switch sm.compressionConfig.Type {
	case GzipCompression:
		var buf bytes.Buffer
		writer, err := gzip.NewWriterLevel(&buf, sm.compressionConfig.Level)
		if err != nil {
			return data, false, err
		}

		if _, err := writer.Write(data); err != nil {
			writer.Close()
			return data, false, err
		}

		if err := writer.Close(); err != nil {
			return data, false, err
		}

		compressed := buf.Bytes()
		if len(compressed) < len(data) {
			sm.mu.Lock()
			sm.compressionSaved += uint64(len(data) - len(compressed))
			sm.mu.Unlock()
			return compressed, true, nil
		}
	}

	return data, false, nil
}

// decompressMessage décompresse un message si nécessaire
func (sm *SimpleMessenger) decompressMessage(data []byte, compressed bool) ([]byte, error) {
	if !compressed {
		return data, nil
	}

	switch sm.compressionConfig.Type {
	case GzipCompression:
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, reader); err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}

	return data, nil
}

// SendMessage envoie un message sécurisé avec compression - MODIFIÉ pour type
func (sm *SimpleMessenger) SendMessage(message string, messageType string, recipient string, sessionToken string, conn io.Writer) error {
	sm.mu.RLock()
	if !sm.isConnected || sm.channel == nil {
		sm.mu.RUnlock()
		return ErrNotConnected
	}

	channel := sm.channel
	sm.mu.RUnlock()

	// Préparer les données
	messageBytes := []byte(message)
	originalSize := len(messageBytes)

	// Compression si activée
	compressedData, isCompressed, err := sm.compressMessage(messageBytes)
	if err != nil {
		return fmt.Errorf("compression failed: %w", err)
	}

	// Créer un message avec métadonnées
	metadata := map[string]interface{}{
		"compressed":    isCompressed,
		"original_size": originalSize,
	}

	// Sérialiser métadonnées + données
	finalData, err := sm.serializeWithMetadata(compressedData, metadata)
	if err != nil {
		return fmt.Errorf("serialization failed: %w", err)
	}

	// Envoyer via le canal sécurisé avec FS et type de message
	err = channel.SendMessage(finalData, messageType, recipient, sessionToken, conn)

	if err == nil {
		// Mettre à jour les statistiques
		sm.mu.Lock()
		sm.messagesSent++
		sm.bytesSent += uint64(originalSize)
		sm.mu.Unlock()
	}

	return err
}

// ReceiveMessage reçoit un message sécurisé avec décompression - MODIFIÉ pour type
func (sm *SimpleMessenger) ReceiveMessage(conn io.Reader) (string, string, string, string, error) {
	sm.mu.RLock()
	if !sm.isConnected || sm.channel == nil {
		sm.mu.RUnlock()
		return "", "", "", "", ErrNotConnected
	}

	channel := sm.channel
	sm.mu.RUnlock()

	// Recevoir via le canal sécurisé avec FS et type de message
	finalData, messageType, recipient, sessionToken, err := channel.ReceiveMessage(conn)
	if err != nil {
		// Vérifier si c'est un ping
		if err.Error() == "receive timeout" {
			return "", "", "", "", err
		}
		return "", "", "", "", err
	}

	// Désérialiser métadonnées + données
	messageBytes, metadata, err := sm.deserializeWithMetadata(finalData)
	if err != nil {
		return "", "", "", "", fmt.Errorf("deserialization failed: %w", err)
	}

	// Décompression si nécessaire
	isCompressed, _ := metadata["compressed"].(bool)
	decompressedData, err := sm.decompressMessage(messageBytes, isCompressed)
	if err != nil {
		return "", "", "", "", fmt.Errorf("decompression failed: %w", err)
	}

	message := string(decompressedData)

	// Gérer les messages de keep-alive
	if sm.isKeepAliveMessage(message) {
		sm.handleKeepAliveMessage(message, messageType, recipient, sessionToken)
		// Recevoir le message suivant
		return sm.ReceiveMessage(conn)
	}

	// Mettre à jour les statistiques
	sm.mu.Lock()
	sm.messagesReceived++
	sm.bytesReceived += uint64(len(decompressedData))
	sm.mu.Unlock()

	return message, messageType, recipient, sessionToken, nil
}

// isKeepAliveMessage vérifie si c'est un message de keep-alive
func (sm *SimpleMessenger) isKeepAliveMessage(message string) bool {
	return len(message) > 5 && (message[:5] == "PING:" || message[:5] == "PONG:")
}

// handleKeepAliveMessage traite les messages de keep-alive - MODIFIÉ pour type
func (sm *SimpleMessenger) handleKeepAliveMessage(message string, messageType string, recipient string, sessionToken string) {
	if len(message) > 5 && message[:5] == "PING:" {
		// Répondre au ping
		pongMsg := "PONG:" + message[5:]
		if sm.conn != nil {
			sm.SendMessage(pongMsg, "pong", "system", "pong-session", sm.conn.(io.Writer))
		}
	} else if len(message) > 5 && message[:5] == "PONG:" {
		// Marquer le pong reçu
		sm.mu.Lock()
		sm.lastPong = time.Now()
		sm.missedPings = 0
		sm.mu.Unlock()
	}
}

// serializeWithMetadata sérialise données + métadonnées
func (sm *SimpleMessenger) serializeWithMetadata(data []byte, metadata map[string]interface{}) ([]byte, error) {
	// Format simple: [1 byte flags][data]
	flags := byte(0)
	if compressed, ok := metadata["compressed"].(bool); ok && compressed {
		flags |= 0x01
	}

	result := make([]byte, 1+len(data))
	result[0] = flags
	copy(result[1:], data)

	return result, nil
}

// deserializeWithMetadata désérialise données + métadonnées
func (sm *SimpleMessenger) deserializeWithMetadata(data []byte) ([]byte, map[string]interface{}, error) {
	if len(data) < 1 {
		return nil, nil, errors.New("invalid data format")
	}

	flags := data[0]
	messageData := data[1:]

	metadata := map[string]interface{}{
		"compressed": (flags & 0x01) != 0,
	}

	return messageData, metadata, nil
}

// IsConnected retourne l'état de la connexion
func (sm *SimpleMessenger) IsConnected() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.isConnected
}

// IsReconnecting retourne l'état de reconnexion
func (sm *SimpleMessenger) IsReconnecting() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.isReconnecting
}

// Close ferme la connexion et nettoie les ressources
func (sm *SimpleMessenger) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isConnected && !sm.isReconnecting {
		return nil
	}

	// Arrêter tous les services
	close(sm.stopChan)
	close(sm.stopPing)

	if sm.pingTicker != nil {
		sm.pingTicker.Stop()
	}

	if sm.channel != nil {
		sm.channel.Close()
		sm.channel = nil
	}

	sm.isConnected = false
	sm.isReconnecting = false

	// Attendre que toutes les goroutines se terminent
	sm.mu.Unlock()
	sm.wg.Wait()
	sm.mu.Lock()

	return nil
}

// GetStats retourne les statistiques du messenger avec nouvelles métriques
func (sm *SimpleMessenger) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := map[string]interface{}{
		"is_initiator":       sm.isInitiator,
		"is_connected":       sm.isConnected,
		"is_reconnecting":    sm.isReconnecting,
		"start_time":         sm.startTime,
		"uptime":             time.Since(sm.startTime),
		"last_connect_time":  sm.lastConnectTime,
		"messages_sent":      sm.messagesSent,
		"messages_received":  sm.messagesReceived,
		"bytes_sent":         sm.bytesSent,
		"bytes_received":     sm.bytesReceived,
		"reconnect_attempts": sm.reconnectAttempts,
		"reconnect_count":    sm.reconnectCount,
		"compression_saved":  sm.compressionSaved,
		"missed_pings":       sm.missedPings,
		"last_ping":          sm.lastPing,
		"last_pong":          sm.lastPong,
		"algorithms": map[string]string{
			"key_exchange":    "Kyber768",
			"encryption":      "NaCl-secretbox",
			"kdf":             "HKDF-SHA256",
			"forward_secrecy": "Enabled",
		},
		"features": map[string]bool{
			"reconnect_enabled":       sm.reconnectPolicy.Enabled,
			"keepalive_enabled":       sm.keepAliveConfig.Enabled,
			"compression_enabled":     sm.compressionConfig.Enabled,
			"forward_secrecy_enabled": sm.keyRotationConfig.Enabled,
		},
	}

	if sm.keyExchange != nil {
		stats["key_exchange_overhead"] = sm.keyExchange.GetKeyExchangeOverhead()
	}

	if sm.channel != nil {
		stats["message_overhead"] = sm.channel.GetOverhead()
		stats["key_rotation"] = sm.channel.GetRotationStats()
	}

	return stats
}

// SendWithTimeout envoie un message avec timeout - MODIFIÉ pour type
func (sm *SimpleMessenger) SendWithTimeout(message string, messageType string, recipient string, sessionToken string, conn io.Writer, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		done <- sm.SendMessage(message, messageType, recipient, sessionToken, conn)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return errors.New("send timeout")
	}
}

// ReceiveWithTimeout reçoit un message avec timeout - MODIFIÉ pour type
func (sm *SimpleMessenger) ReceiveWithTimeout(conn io.Reader, timeout time.Duration) (string, string, string, string, error) {
	type result struct {
		message      string
		messageType  string
		recipient    string
		sessionToken string
		err          error
	}

	done := make(chan result, 1)

	go func() {
		msg, msgType, recipient, sessionToken, err := sm.ReceiveMessage(conn)
		done <- result{message: msg, messageType: msgType, recipient: recipient, sessionToken: sessionToken, err: err}
	}()

	select {
	case res := <-done:
		return res.message, res.messageType, res.recipient, res.sessionToken, res.err
	case <-time.After(timeout):
		return "", "", "", "", errors.New("receive timeout")
	}
}

// NOUVELLES MÉTHODES pour Forward Secrecy

// ForceKeyRotation force une rotation des clés immédiate
func (sm *SimpleMessenger) ForceKeyRotation() error {
	sm.mu.RLock()
	if !sm.isConnected || sm.channel == nil {
		sm.mu.RUnlock()
		return ErrNotConnected
	}

	channel := sm.channel
	sm.mu.RUnlock()

	channel.ForceRotation()
	return nil
}

// GetKeyRotationStats retourne les statistiques de rotation des clés
func (sm *SimpleMessenger) GetKeyRotationStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.channel == nil {
		return map[string]interface{}{
			"forward_secrecy_enabled": false,
		}
	}

	return sm.channel.GetRotationStats()
}

// SetMaxOldKeys configure le nombre maximum d'anciennes clés à conserver
func (sm *SimpleMessenger) SetMaxOldKeys(max int) {
	sm.mu.RLock()
	if sm.channel != nil {
		sm.channel.SetMaxOldChannels(max)
	}
	sm.mu.RUnlock()
}

// CreateSecureConnection fonction utilitaire pour créer une connexion complète
func CreateSecureConnection(conn io.ReadWriter, isInitiator bool) (*SimpleMessenger, error) {
	messenger := NewSimpleMessenger(isInitiator)

	if err := messenger.Connect(conn); err != nil {
		return nil, fmt.Errorf("failed to establish secure connection: %w", err)
	}

	return messenger, nil
}

// CreateSecureConnectionWithReconnect crée une connexion avec support de reconnexion
func CreateSecureConnectionWithReconnect(connector ConnectorFunc, isInitiator bool) (*SimpleMessenger, error) {
	messenger := NewSimpleMessenger(isInitiator)

	if err := messenger.ConnectWithReconnect(connector); err != nil {
		return nil, fmt.Errorf("failed to establish secure connection with reconnect: %w", err)
	}

	return messenger, nil
}

// CreateSecureConnectionWithFS crée une connexion avec Forward Secrecy personnalisé
func CreateSecureConnectionWithFS(conn io.ReadWriter, isInitiator bool, fsConfig *KeyRotationConfig) (*SimpleMessenger, error) {
	messenger := NewSimpleMessenger(isInitiator)

	// Configurer Forward Secrecy avant la connexion
	if fsConfig != nil {
		messenger.SetKeyRotationConfig(fsConfig)
	}

	if err := messenger.Connect(conn); err != nil {
		return nil, fmt.Errorf("failed to establish secure connection with FS: %w", err)
	}

	return messenger, nil
}
